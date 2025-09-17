import path from "path";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import selfsigned from "selfsigned";
import { TopicStore, SchemaInfo, EventEnvelope } from "./pubsub/topicStore";
import { TokenVerifier } from "./auth/mockOAuth";

type PubSubPackage = {
  com: {
    salesforce: {
      eventbus: {
        proto: {
          PubSub: grpc.ServiceClientConstructor & { service: grpc.ServiceDefinition<unknown> };
        };
      };
    };
  };
};

export const PROTO_PATH = path.join(
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

export const pubsubProto = grpc.loadPackageDefinition(packageDefinition) as unknown as PubSubPackage;

export interface TLSOptions {
  enabled?: boolean;
  privateKey?: Buffer | string;
  certChain?: Buffer | string;
  rootCerts?: Buffer | string;
  selfSigned?: boolean;
  selfSignedOptions?: SelfSignedOptions;
}

export interface SelfSignedOptions {
  commonName?: string;
  altNames?: Array<{ type: number; value?: string; ip?: string }>;
  days?: number;
  keySize?: number;
}

export interface MockPubSubServerOptions {
  oauth: TokenVerifier;
  requiredScope?: string;
  tls?: TLSOptions;
}

export interface MockPubSubServer {
  server: grpc.Server;
  credentials: grpc.ServerCredentials;
  tls: {
    enabled: boolean;
    privateKey: Buffer | null;
    certChain: Buffer | null;
    rootCerts: Buffer | null;
  };
  getDebugState(): { topics: Map<string, TopicMapEntry> };
}

interface PublishRequestEvent {
  payload?: Buffer | Uint8Array | string;
}

interface PublishRequest {
  topic_name?: string;
  events?: PublishRequestEvent[];
  schema_info?: SchemaInfo;
}

interface PublishResultMessage {
  success: boolean;
  error_message: string;
  status_code: number;
  replay_id: { value: Buffer };
}

interface PublishResponseMessage {
  results: PublishResultMessage[];
}

interface SubscriptionRequest {
  topic_name?: string;
  replay_preset?: string;
  replay_id?: { value?: Buffer | Uint8Array | string } | Buffer | Uint8Array | string;
  num_requested?: number;
}

interface FetchResponse {
  events: Array<{ replay_id: Buffer; payload: Buffer }>;
  pending: boolean;
}

interface TopicMapEntry {
  store: TopicStore;
}

function createGrpcError(code: grpc.status, message: string, details?: unknown): grpc.ServiceError {
  const error = new Error(message) as grpc.ServiceError;
  error.code = code;
  if (details) {
    error.details = typeof details === "string" ? details : JSON.stringify(details);
  }
  return error;
}

function normalizeToBuffer(value?: Buffer | string | null): Buffer | null {
  if (!value) {
    return null;
  }
  if (Buffer.isBuffer(value)) {
    return value;
  }
  return Buffer.from(value);
}

function generateReplayId(counter: number): Buffer {
  const buffer = Buffer.alloc(15, 0);
  let value = counter;
  for (let idx = 14; idx >= 0 && value > 0; idx -= 1) {
    buffer[idx] = value & 0xff;
    value >>= 8;
  }
  return buffer;
}

function mapIncomingEvent(event: PublishRequestEvent): Buffer {
  if (Buffer.isBuffer(event.payload)) {
    return event.payload;
  }
  if (event.payload instanceof Uint8Array) {
    return Buffer.from(event.payload);
  }
  if (typeof event.payload === "string") {
    return Buffer.from(event.payload, "utf8");
  }
  return Buffer.alloc(0);
}

function prepareTopic(topics: Map<string, TopicMapEntry>, topicName: string, schemaInfo?: SchemaInfo | null): TopicMapEntry {
  if (!topics.has(topicName)) {
    topics.set(topicName, { store: new TopicStore(schemaInfo ?? null) });
  }
  const entry = topics.get(topicName)!;
  entry.store.updateSchemaInfo(schemaInfo ?? null);
  return entry;
}

function extractReplayBuffer(message?: SubscriptionRequest["replay_id"]): Buffer | null {
  if (!message) {
    return null;
  }
  if (Buffer.isBuffer(message)) {
    return message;
  }
  if (message instanceof Uint8Array) {
    return Buffer.from(message);
  }
  if (typeof message === "string") {
    return Buffer.from(message, "base64");
  }
  if (typeof message === "object" && "value" in message && message.value !== undefined) {
    return extractReplayBuffer(message.value as Buffer | string | Uint8Array);
  }
  return null;
}

function authenticate(metadata: grpc.Metadata, oauth: TokenVerifier, requiredScope: string): void {
  const raw = metadata.get("authorization");
  if (!raw || raw.length === 0) {
    throw createGrpcError(grpc.status.UNAUTHENTICATED, "Authorization metadata missing");
  }

  const header = raw[0];
  if (typeof header !== "string") {
    throw createGrpcError(grpc.status.UNAUTHENTICATED, "Authorization header must be a string");
  }

  const match = /^Bearer\s+(.+)/i.exec(header);
  if (!match) {
    throw createGrpcError(grpc.status.UNAUTHENTICATED, "Authorization header must use Bearer token");
  }

  const token = match[1];
  let payload: ReturnType<TokenVerifier["verify"]>;
  try {
    payload = oauth.verify(token);
  } catch (err) {
    throw createGrpcError(grpc.status.UNAUTHENTICATED, "Invalid access token", err instanceof Error ? err.message : err);
  }

  const rawScopes = Array.isArray(payload.scope)
    ? payload.scope
    : String(payload.scope ?? "")
        .split(/\s+/)
        .filter(Boolean);
  const scopes = new Set(rawScopes);
  if (!scopes.has(requiredScope)) {
    throw createGrpcError(grpc.status.PERMISSION_DENIED, "Token is missing required scope");
  }
}

function generateSelfSignedCertificate(options: SelfSignedOptions = {}): {
  privateKey: Buffer;
  certChain: Buffer;
  rootCerts: Buffer;
} {
  const attributes = [{ name: "commonName", value: options.commonName ?? "localhost" }];
  const pems = selfsigned.generate(attributes, {
    keySize: options.keySize ?? 2048,
    days: options.days ?? 365,
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
      {
        name: "subjectAltName",
        altNames:
          options.altNames ?? [
            { type: 2, value: "localhost" },
            { type: 7, ip: "127.0.0.1" },
          ],
      },
    ],
  });
  const privateKey = Buffer.from(pems.private);
  const certChain = Buffer.from(pems.cert);
  return {
    privateKey,
    certChain,
    rootCerts: certChain,
  };
}

function prepareServerCredentials(tls: TLSOptions | undefined): {
  enabled: boolean;
  privateKey: Buffer | null;
  certChain: Buffer | null;
  rootCerts: Buffer | null;
  credentials: grpc.ServerCredentials;
} {
  const enabled = tls?.enabled ?? true;
  if (!enabled) {
    return {
      enabled: false,
      privateKey: null,
      certChain: null,
      rootCerts: null,
      credentials: grpc.ServerCredentials.createInsecure(),
    };
  }

  let privateKey = normalizeToBuffer(tls?.privateKey);
  let certChain = normalizeToBuffer(tls?.certChain);
  let rootCerts = normalizeToBuffer(tls?.rootCerts);

  if ((!privateKey || !certChain) && (tls?.selfSigned ?? true)) {
    const generated = generateSelfSignedCertificate(tls?.selfSignedOptions);
    privateKey = generated.privateKey;
    certChain = generated.certChain;
    rootCerts = generated.rootCerts;
  }

  if (!privateKey || !certChain) {
    throw new Error("TLS is enabled but privateKey/certChain were not provided and selfSigned generation is disabled");
  }

  const normalizedRoot = rootCerts ?? certChain;
  const credentials = grpc.ServerCredentials.createSsl(normalizedRoot, [
    {
      private_key: privateKey,
      cert_chain: certChain,
    },
  ]);

  return {
    enabled: true,
    privateKey,
    certChain,
    rootCerts: normalizedRoot,
    credentials,
  };
}

export function createMockPubSubServer(options: MockPubSubServerOptions): MockPubSubServer {
  const { oauth, requiredScope = "eventbus.pubsub", tls } = options;
  if (!oauth || typeof oauth.verify !== "function") {
    throw new Error("A token verifier implementing verify(token) is required");
  }

  const topics = new Map<string, TopicMapEntry>();
  const tlsContext = prepareServerCredentials(tls);
  const server = new grpc.Server();
  const pubsubServiceDefinition = pubsubProto.com.salesforce.eventbus.proto.PubSub.service;

  const publish: grpc.handleUnaryCall<PublishRequest, PublishResponseMessage> = (call, callback) => {
    try {
      authenticate(call.metadata, oauth, requiredScope);
    } catch (error) {
      callback(error as grpc.ServiceError);
      return;
    }

    const { topic_name: topicName, events = [], schema_info: schemaInfo } = call.request;
    if (!topicName) {
      callback(createGrpcError(grpc.status.INVALID_ARGUMENT, "topic_name is required"));
      return;
    }

    const topicEntry = prepareTopic(topics, topicName, schemaInfo ?? null);

    const results = events.map((event) => {
      const payload = mapIncomingEvent(event);
      const replayId = generateReplayId(topicEntry.store.nextReplayId());
      topicEntry.store.append({ replayId, payload });
      return {
        success: true,
        error_message: "",
        status_code: grpc.status.OK,
        replay_id: { value: replayId },
      } satisfies PublishResultMessage;
    });

    callback(null, { results });
  };

  const subscribe: grpc.handleServerStreamingCall<SubscriptionRequest, FetchResponse> = (call) => {
    (async () => {
      try {
        authenticate(call.metadata, oauth, requiredScope);
      } catch (error) {
        call.emit("error", error as grpc.ServiceError);
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

      const topicEntry = topics.get(topicName);
      if (!topicEntry) {
        call.write({ events: [], pending: false });
        call.end();
        return;
      }

      const { store } = topicEntry;
      const snapshot = store.snapshot();
      const totalEvents = snapshot.events.length;
      const requestCount = numRequested ?? totalEvents;
      const replayIdBuffer = extractReplayBuffer(replayIdMessage);
      let startIndex = 0;

      switch (replayPreset) {
        case "LATEST":
          startIndex = totalEvents > 0 ? Math.max(totalEvents - requestCount, 0) : 0;
          break;
        case "CUSTOM":
          if (replayIdBuffer) {
            const index = store.findReplayIndex(replayIdBuffer);
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

      const events = await store.slice(startIndex, requestCount);      const responseEvents = events.map((event: EventEnvelope) => ({
        replay_id: event.replayId,
        payload: event.payload,
      }));

      call.write({ events: responseEvents, pending: false });
      call.end();
    })().catch((error) => {
      call.emit("error", error as grpc.ServiceError);
    });
  };

  const getTopic: grpc.handleUnaryCall<{ topic_name?: string }, { topic_name: string; schema_info: SchemaInfo | null }> = (
    call,
    callback,
  ) => {
    try {
      authenticate(call.metadata, oauth, requiredScope);
    } catch (error) {
      callback(error as grpc.ServiceError);
      return;
    }

    const { topic_name: topicName } = call.request;
    if (!topicName) {
      callback(createGrpcError(grpc.status.INVALID_ARGUMENT, "topic_name is required"));
      return;
    }

    const topicEntry = topics.get(topicName);
    if (!topicEntry) {
      callback(createGrpcError(grpc.status.NOT_FOUND, "Topic not found"));
      return;
    }

    callback(null, {
      topic_name: topicName,
      schema_info: topicEntry.store.getSchemaInfo(),
    });
  };

  server.addService(pubsubServiceDefinition, {
    Publish: publish,
    Subscribe: subscribe,
    GetTopic: getTopic,
  });

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







