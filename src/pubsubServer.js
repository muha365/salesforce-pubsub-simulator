const path = require("path");
const grpc = require("@grpc/grpc-js");
const protoLoader = require("@grpc/proto-loader");
const selfsigned = require("selfsigned");

const PROTO_PATH = path.join(
  __dirname,
  "..",
  "proto",
  "com",
  "salesforce",
  "eventbus",
  "proto",
  "pubsub_api.proto",
);

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

const pubsubProto = grpc.loadPackageDefinition(packageDefinition).com.salesforce.eventbus.proto;

function createGrpcError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  if (details) {
    error.details = details;
  }
  return error;
}

function bufferKey(buffer) {
  return Buffer.from(buffer || []).toString("base64");
}

function normalizeToBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  return Buffer.from(value || "");
}

function generateSelfSignedCertificate(options = {}) {
  const {
    commonName = "localhost",
    altNames = [
      { type: 2, value: "localhost" },
      { type: 7, ip: "127.0.0.1" },
    ],
    days = 365,
    keySize = 2048,
  } = options;

  const attributes = [{ name: "commonName", value: commonName }];
  const pems = selfsigned.generate(attributes, {
    keySize,
    days,
    extensions: [
      { name: "basicConstraints", cA: true },
      {
        name: "keyUsage",
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true,
      },
      { name: "extKeyUsage", serverAuth: true, clientAuth: true },
      { name: "subjectAltName", altNames },
    ],
  });

  return {
    privateKey: normalizeToBuffer(pems.private),
    certChain: normalizeToBuffer(pems.cert),
    rootCerts: normalizeToBuffer(pems.cert),
  };
}

function prepareServerCredentials(tlsOptions = {}) {
  const { enabled = true } = tlsOptions;

  if (!enabled) {
    return {
      enabled: false,
      privateKey: null,
      certChain: null,
      rootCerts: null,
      credentials: grpc.ServerCredentials.createInsecure(),
    };
  }

  let { privateKey, certChain, rootCerts, selfSigned = true, selfSignedOptions } = tlsOptions;

  if ((!privateKey || !certChain) && selfSigned) {
    const generated = generateSelfSignedCertificate(selfSignedOptions);
    privateKey = generated.privateKey;
    certChain = generated.certChain;
    rootCerts = generated.rootCerts;
  }

  if (!privateKey || !certChain) {
    throw new Error(
      "TLS is enabled but privateKey/certChain were not provided and selfSigned generation is disabled",
    );
  }

  const normalizedPrivateKey = normalizeToBuffer(privateKey);
  const normalizedCertChain = normalizeToBuffer(certChain);
  const normalizedRootCerts = rootCerts ? normalizeToBuffer(rootCerts) : normalizedCertChain;

  return {
    enabled: true,
    privateKey: normalizedPrivateKey,
    certChain: normalizedCertChain,
    rootCerts: normalizedRootCerts,
    credentials: grpc.ServerCredentials.createSsl(normalizedRootCerts, [
      {
        private_key: normalizedPrivateKey,
        cert_chain: normalizedCertChain,
      },
    ]),
  };
}

function createMockPubSubServer(options = {}) {
  const { oauth, requiredScope = "eventbus.pubsub", tls = {} } = options;

  if (!oauth || typeof oauth.verify !== "function") {
    throw new Error("A token verifier implementing verify(token) is required");
  }

  const topics = new Map();
  const tlsContext = prepareServerCredentials(tls);

  function authenticate(metadata) {
    const raw = metadata.get("authorization");
    if (!raw || raw.length === 0) {
      throw createGrpcError(grpc.status.UNAUTHENTICATED, "Authorization metadata missing");
    }

    const header = raw[0];
    const match = /^Bearer\s+(.+)/i.exec(header);
    if (!match) {
      throw createGrpcError(grpc.status.UNAUTHENTICATED, "Authorization header must use Bearer token");
    }

    const token = match[1];

    let payload;
    try {
      payload = oauth.verify(token);
    } catch (err) {
      throw createGrpcError(grpc.status.UNAUTHENTICATED, "Invalid access token", err.details);
    }

    const rawScopes = Array.isArray(payload.scope)
      ? payload.scope
      : String(payload.scope || "")
          .split(/\s+/)
          .filter(Boolean);
    const scopes = new Set(rawScopes);
    if (!scopes.has(requiredScope)) {
      throw createGrpcError(grpc.status.PERMISSION_DENIED, "Token is missing required scope");
    }

    return payload;
  }

  function ensureTopic(topicName, schemaInfo) {
    if (!topics.has(topicName)) {
      topics.set(topicName, {
        schemaInfo: schemaInfo || null,
        events: [],
        replayCounter: 0,
      });
    }

    const topic = topics.get(topicName);
    if (schemaInfo) {
      topic.schemaInfo = schemaInfo;
    }
    return topic;
  }

  function mapIncomingEvent(event) {
    const payload = Buffer.isBuffer(event.payload)
      ? event.payload
      : Buffer.from(event.payload || "");
    return { payload };
  }

  function generateReplayId(counter) {
    const buffer = Buffer.alloc(15);
    let value = counter;
    for (let i = 14; i >= 0 && value > 0; i--) {
      buffer[i] = value & 0xff;
      value >>= 8;
    }
    return buffer;
  }

  function assignReplayId(topic, event) {
    const replayCounter = topic.replayCounter++;
    const replayIdBuffer = generateReplayId(replayCounter);
    const storedEvent = {
      replayId: replayIdBuffer,
      payload: event.payload,
    };
    topic.events.push(storedEvent);

    return {
      success: true,
      error_message: "",
      status_code: grpc.status.OK,
      replay_id: { value: replayIdBuffer },
    };
  }

  function publish(call, callback) {
    try {
      authenticate(call.metadata);
    } catch (error) {
      callback(error);
      return;
    }

    const { topic_name: topicName, events = [], schema_info: schemaInfo } = call.request;

    if (!topicName) {
      callback(createGrpcError(grpc.status.INVALID_ARGUMENT, "topic_name is required"));
      return;
    }

    const topic = ensureTopic(topicName, schemaInfo);

    const normalizedEvents = events.map(mapIncomingEvent);
    const results = normalizedEvents.map((event) => assignReplayId(topic, event));

    callback(null, { results });
  }

  function subscribe(call) {
    try {
      authenticate(call.metadata);
    } catch (error) {
      call.emit("error", error);
      return;
    }

    const {
      topic_name: topicName,
      replay_preset: replayPreset = "REPLAY_PRESET_UNSPECIFIED",
      replay_id: replayIdMessage,
      num_requested: numRequested,
    } = call.request;

    if (!topicName) {
      call.emit("error", createGrpcError(grpc.status.INVALID_ARGUMENT, "topic_name is required"));
      return;
    }

    const topic = topics.get(topicName);

    if (!topic) {
      call.write({ events: [], pending: false });
      call.end();
      return;
    }

    let startIndex = 0;
    const requestedCount = numRequested || topic.events.length;
    const totalEvents = topic.events.length;
    const replayIdBuffer = replayIdMessage && replayIdMessage.value ? Buffer.from(replayIdMessage.value) : null;

    switch (replayPreset) {
      case "LATEST":
        startIndex = totalEvents > 0 ? Math.max(totalEvents - requestedCount, 0) : 0;
        break;
      case "CUSTOM":
        if (replayIdBuffer) {
          const key = bufferKey(replayIdBuffer);
          const index = topic.events.findIndex((evt) => bufferKey(evt.replayId) === key);
          startIndex = index >= 0 ? Math.min(index + 1, totalEvents) : totalEvents;
        } else {
          startIndex = totalEvents;
        }
        break;
      case "EARLIEST":
      case "REPLAY_PRESET_UNSPECIFIED":
      default:
        startIndex = 0;
        break;
    }

    const slice = topic.events.slice(startIndex, startIndex + requestedCount);
    const responseEvents = slice.map((evt) => ({
      replay_id: evt.replayId,
      payload: evt.payload,
    }));

    call.write({ events: responseEvents, pending: false });
    call.end();
  }

  function getTopic(call, callback) {
    try {
      authenticate(call.metadata);
    } catch (error) {
      callback(error);
      return;
    }

    const { topic_name: topicName } = call.request;
    if (!topicName) {
      callback(createGrpcError(grpc.status.INVALID_ARGUMENT, "topic_name is required"));
      return;
    }

    const topic = topics.get(topicName);
    if (!topic) {
      callback(createGrpcError(grpc.status.NOT_FOUND, "Topic not found"));
      return;
    }

    callback(null, {
      topic_name: topicName,
      schema_info: topic.schemaInfo || null,
    });
  }

  const server = new grpc.Server();
  server.addService(pubsubProto.PubSub.service, {
    Publish: publish,
    Subscribe: subscribe,
    GetTopic: getTopic,
  });

  server.getDebugState = () => ({ topics });

  return {
    server,
    credentials: tlsContext.credentials,
    tls: {
      enabled: tlsContext.enabled,
      privateKey: tlsContext.privateKey,
      certChain: tlsContext.certChain,
      rootCerts: tlsContext.rootCerts,
    },
    getDebugState: () => ({ topics }),
  };
}

module.exports = {
  createMockPubSubServer,
  pubsubProto,
  PROTO_PATH,
  prepareServerCredentials,
  generateSelfSignedCertificate,
};

