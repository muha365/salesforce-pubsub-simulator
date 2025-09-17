const grpc = require("@grpc/grpc-js");
const { createMockPubSubServer, pubsubProto } = require("../../src/pubsubServer");
const { MockOAuthServer } = require("../../src/mockOAuth");

function metadataWithToken(token) {
  const metadata = new grpc.Metadata();
  metadata.add("authorization", `Bearer ${token}`);
  return metadata;
}

function toBuffer(value) {
  if (!value) {
    return Buffer.alloc(0);
  }
  if (Buffer.isBuffer(value)) {
    return Buffer.from(value);
  }
  if (value.value) {
    return Buffer.from(value.value);
  }
  if (Array.isArray(value)) {
    return Buffer.from(value);
  }
  return Buffer.from(value);
}

function bufferToBigInt(buffer) {
  let result = 0n;
  for (const byte of buffer) {
    result = (result << 8n) + BigInt(byte);
  }
  return result;
}

describe("Mock Salesforce Pub/Sub OAuth integration", () => {
  let oauth;
  let server;
  let client;
  let mockServer;

  const topicName = "/event/MockTopic__e";

  beforeAll(async () => {
    oauth = new MockOAuthServer({
      signingSecret: "test-signing-secret",
      tokenLifetimeSeconds: 60,
    });

    oauth.registerClient("publisher", "super-secret", ["eventbus.pubsub", "refresh"]);
    oauth.registerClient("limited", "limited-secret", ["limited.scope"]);

    mockServer = createMockPubSubServer({ oauth, requiredScope: "eventbus.pubsub" });
    server = mockServer.server;

    const port = await new Promise((resolve, reject) => {
      server.bindAsync(
        "127.0.0.1:0",
        mockServer.credentials,
        (error, actualPort) => {
          if (error) {
            reject(error);
            return;
          }
          resolve(actualPort);
        },
      );
    });
    server.start();

    const ClientCtor = pubsubProto.PubSub;
    const clientCredentials = mockServer.tls.enabled
      ? grpc.credentials.createSsl(mockServer.tls.rootCerts)
      : grpc.credentials.createInsecure();
    client = new ClientCtor(`127.0.0.1:${port}`, clientCredentials);
  });

  afterAll(async () => {
    if (client) {
      client.close();
    }

    if (server) {
      await new Promise((resolve, reject) => {
        server.tryShutdown((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    }
  });

  function callPublish(request, metadata) {
    const method = client.publish ? client.publish.bind(client) : client.Publish.bind(client);
    return new Promise((resolve, reject) => {
      method(request, metadata, (error, response) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(response);
      });
    });
  }

  function publishWithToken(token, request) {
    return callPublish(request, metadataWithToken(token));
  }

  function callSubscribe(request, metadata) {
    const method = client.subscribe ? client.subscribe.bind(client) : client.Subscribe.bind(client);
    return new Promise((resolve, reject) => {
      const stream = method(request, metadata);
      const responses = [];
      stream.on("data", (data) => responses.push(data));
      stream.on("error", (error) => reject(error));
      stream.on("end", () => resolve(responses));
    });
  }

  function subscribeWithToken(token, request) {
    return callSubscribe(request, metadataWithToken(token));
  }

  function callGetTopic(request, metadata) {
    const method = client.getTopic ? client.getTopic.bind(client) : client.GetTopic.bind(client);
    return new Promise((resolve, reject) => {
      method(request, metadata, (error, response) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(response);
      });
    });
  }

  function getTopicWithToken(token, request) {
    return callGetTopic(request, metadataWithToken(token));
  }

  test("allows publish and subscribe with a valid OAuth token", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;

    const payload = Buffer.from(JSON.stringify({ message: "hello" }));
    const publishResponse = await publishWithToken(token, {
      topic_name: topicName,
      schema_info: { schema_id: "1", schema_version: "1" },
      events: [{ payload }],
    });

    expect(publishResponse.results).toHaveLength(1);
    expect(publishResponse.results[0].success).toBe(true);

    const replayIdBuffer = toBuffer(publishResponse.results[0].replay_id);
    expect(replayIdBuffer.length).toBe(15);


    const responses = await subscribeWithToken(token, {
      topic_name: topicName,
      replay_preset: "EARLIEST",
      num_requested: 10,
    });

    expect(responses.length).toBe(1);
    const firstBatch = responses[0];
    expect(firstBatch.events.length).toBeGreaterThanOrEqual(1);
    const eventPayload = firstBatch.events[0].payload;
    expect(Buffer.from(eventPayload).toString()).toContain("hello");
  });

  test("rejects requests that use an invalid token", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;

    const invalidToken = `${token}tampered`;

    await expect(
      publishWithToken(invalidToken, {
        topic_name: topicName,
        events: [{ payload: Buffer.from("unauthorized") }],
      }),
    ).rejects.toMatchObject({ code: grpc.status.UNAUTHENTICATED });
  });

  test("rejects tokens missing the required scope", async () => {
    const limitedToken = oauth.issueToken({
      clientId: "limited",
      clientSecret: "limited-secret",
      scope: "limited.scope",
    }).access_token;

    await expect(
      publishWithToken(limitedToken, {
        topic_name: topicName,
        events: [{ payload: Buffer.from("forbidden") }],
      }),
    ).rejects.toMatchObject({ code: grpc.status.PERMISSION_DENIED });
  });

  test("supports sequential publish and subscribe operations", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;
    const sequenceTopic = `${topicName}_sequence`;

    const firstPayload = Buffer.from(JSON.stringify({ message: "first publish" }));
    await publishWithToken(token, {
      topic_name: sequenceTopic,
      events: [{ payload: firstPayload }],
    });

    const secondPayload = Buffer.from(JSON.stringify({ message: "second publish" }));
    await publishWithToken(token, {
      topic_name: sequenceTopic,
      events: [{ payload: secondPayload }],
    });

    const earliestResponses = await subscribeWithToken(token, {
      topic_name: sequenceTopic,
      replay_preset: "EARLIEST",
      num_requested: 10,
    });

    expect(earliestResponses.length).toBe(1);
    const earliestBatch = earliestResponses[0];
    expect(earliestBatch.events).toHaveLength(2);
    const earliestMessages = earliestBatch.events.map((evt) =>
      Buffer.from(evt.payload).toString()
    );
    expect(earliestMessages[0]).toContain("first publish");
    expect(earliestMessages[1]).toContain("second publish");

    const firstReplayIdBuffer = toBuffer(earliestBatch.events[0].replay_id);
    const secondReplayIdBuffer = toBuffer(earliestBatch.events[1].replay_id);
    const firstReplayValue = Number(bufferToBigInt(firstReplayIdBuffer));
    const secondReplayValue = Number(bufferToBigInt(secondReplayIdBuffer));
    expect(firstReplayIdBuffer.length).toBe(15);
    expect(secondReplayIdBuffer.length).toBe(15);
    expect(secondReplayValue).toBe(firstReplayValue + 1);

    const thirdPayload = Buffer.from(JSON.stringify({ message: "third publish" }));
    await publishWithToken(token, {
      topic_name: sequenceTopic,
      events: [{ payload: thirdPayload }],
    });

    const latestResponses = await subscribeWithToken(token, {
      topic_name: sequenceTopic,
      replay_preset: "LATEST",
      num_requested: 1,
    });

    expect(latestResponses.length).toBe(1);
    const latestBatch = latestResponses[0];
    expect(latestBatch.events).toHaveLength(1);
    expect(Buffer.from(latestBatch.events[0].payload).toString()).toContain("third publish");
    const latestReplayBuffer = toBuffer(latestBatch.events[0].replay_id);
    const latestReplayValue = Number(bufferToBigInt(latestReplayBuffer));
    expect(latestReplayBuffer.length).toBe(15);
    expect(latestReplayValue).toBeGreaterThan(secondReplayValue);

    const customResponses = await subscribeWithToken(token, {
      topic_name: sequenceTopic,
      replay_preset: "CUSTOM",
      replay_id: { value: Buffer.from(firstReplayIdBuffer) },
      num_requested: 10,
    });

    expect(customResponses.length).toBe(1);
    const customBatch = customResponses[0];
    expect(customBatch.events).toHaveLength(2);
    const customMessages = customBatch.events.map((evt) =>
      Buffer.from(evt.payload).toString()
    );
    expect(customMessages[0]).toContain("second publish");
    expect(customMessages[1]).toContain("third publish");
    const customReplayValues = customBatch.events.map((evt) =>
      Number(bufferToBigInt(toBuffer(evt.replay_id)))
    );
    expect(customReplayValues).toEqual([secondReplayValue, latestReplayValue]);
  });
  test("rejects requests missing authorization metadata", async () => {
    const request = {
      topic_name: `${topicName}_missing_auth`,
      events: [{ payload: Buffer.from("no auth") }],
    };
    await expect(callPublish(request, new grpc.Metadata())).rejects.toMatchObject({
      code: grpc.status.UNAUTHENTICATED,
    });
  });

  test("rejects authorization headers that are not bearer tokens", async () => {
    const metadata = new grpc.Metadata();
    metadata.add("authorization", "Basic credentials");
    const request = {
      topic_name: `${topicName}_bad_header`,
      events: [{ payload: Buffer.from("bad header") }],
    };

    await expect(callPublish(request, metadata)).rejects.toMatchObject({
      code: grpc.status.UNAUTHENTICATED,
    });
  });

  test("publish requires a topic name", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;

    await expect(
      publishWithToken(token, {
        events: [{ payload: Buffer.from("missing topic") }],
      }),
    ).rejects.toMatchObject({ code: grpc.status.INVALID_ARGUMENT });
  });

  test("subscribe requires a topic name", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;

    await expect(
      subscribeWithToken(token, {
        replay_preset: "EARLIEST",
        num_requested: 1,
      }),
    ).rejects.toMatchObject({ code: grpc.status.INVALID_ARGUMENT });
  });

  test("subscribe to an unknown topic returns an empty batch", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;

    const responses = await subscribeWithToken(token, {
      topic_name: `${topicName}_unknown`,
      replay_preset: "EARLIEST",
      num_requested: 1,
    });

    expect(responses).toHaveLength(1);
    expect(responses[0].events).toHaveLength(0);
    expect(responses[0].pending).toBe(false);
  });

  test("subscribe rejects requests missing authorization metadata", async () => {
    await expect(
      callSubscribe(
        {
          topic_name: `${topicName}_sub_missing_auth`,
          replay_preset: "EARLIEST",
          num_requested: 1,
        },
        new grpc.Metadata(),
      ),
    ).rejects.toMatchObject({ code: grpc.status.UNAUTHENTICATED });
  });

  test("subscribe rejects invalid bearer tokens", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;
    const invalidToken = `${token}tampered`;

    await expect(
      subscribeWithToken(invalidToken, {
        topic_name: `${topicName}_sub_invalid_token`,
        replay_preset: "EARLIEST",
        num_requested: 1,
      }),
    ).rejects.toMatchObject({ code: grpc.status.UNAUTHENTICATED });
  });

  test("subscribe with CUSTOM preset and no replay id returns an empty batch", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;
    const customTopic = `${topicName}_custom_no_replay`;

    await publishWithToken(token, {
      topic_name: customTopic,
      events: [
        { payload: Buffer.from("custom-1") },
        { payload: Buffer.from("custom-2") },
      ],
    });

    const responses = await subscribeWithToken(token, {
      topic_name: customTopic,
      replay_preset: "CUSTOM",
      num_requested: 5,
    });

    expect(responses).toHaveLength(1);
    expect(responses[0].events).toHaveLength(0);
    expect(responses[0].pending).toBe(false);
  });

  test("subscribe with CUSTOM preset and unknown replay id returns an empty batch", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;
    const customTopic = `${topicName}_custom_unknown_replay`;

    await publishWithToken(token, {
      topic_name: customTopic,
      events: [
        { payload: Buffer.from("unknown-1") },
        { payload: Buffer.from("unknown-2") },
      ],
    });

    const invalidReplayId = Buffer.alloc(15, 0xff);

    const responses = await subscribeWithToken(token, {
      topic_name: customTopic,
      replay_preset: "CUSTOM",
      replay_id: { value: invalidReplayId },
      num_requested: 10,
    });

    expect(responses).toHaveLength(1);
    expect(responses[0].events).toHaveLength(0);
    expect(responses[0].pending).toBe(false);
  });
  test("subscribe respects num_requested limits", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;
    const limitedTopic = `${topicName}_limited_batch`;

    await publishWithToken(token, {
      topic_name: limitedTopic,
      events: [
        { payload: Buffer.from("batch-1") },
        { payload: Buffer.from("batch-2") },
        { payload: Buffer.from("batch-3") },
      ],
    });

    const responses = await subscribeWithToken(token, {
      topic_name: limitedTopic,
      replay_preset: "EARLIEST",
      num_requested: 2,
    });

    expect(responses).toHaveLength(1);
    const batch = responses[0];
    expect(batch.events).toHaveLength(2);
    const payloads = batch.events.map((evt) => Buffer.from(evt.payload).toString());
    expect(payloads[0]).toBe("batch-1");
    expect(payloads[1]).toBe("batch-2");
  });

  test("subscribe defaults to earliest events when replay preset is unspecified", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;
    const defaultPresetTopic = `${topicName}_default_preset`;

    await publishWithToken(token, {
      topic_name: defaultPresetTopic,
      events: [
        { payload: Buffer.from("default-1") },
        { payload: Buffer.from("default-2") },
      ],
    });

    const responses = await subscribeWithToken(token, {
      topic_name: defaultPresetTopic,
      num_requested: 1,
    });

    expect(responses).toHaveLength(1);
    const batch = responses[0];
    expect(batch.events).toHaveLength(1);
    expect(Buffer.from(batch.events[0].payload).toString()).toBe("default-1");
  });

  test("getTopic returns stored schema information", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;
    const schemaTopic = `${topicName}_schema`;

    await publishWithToken(token, {
      topic_name: schemaTopic,
      schema_info: { schema_id: "schema-123", schema_version: "2" },
      events: [{ payload: Buffer.from("schema event") }],
    });

    const topicInfo = await getTopicWithToken(token, {
      topic_name: schemaTopic,
    });

    expect(topicInfo.topic_name).toBe(schemaTopic);
    expect(topicInfo.schema_info).toEqual({
      schema_id: "schema-123",
      schema_version: "2",
    });
  });

  test("getTopic requires a topic name", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;

    await expect(
      getTopicWithToken(token, {
        topic_name: "",
      }),
    ).rejects.toMatchObject({ code: grpc.status.INVALID_ARGUMENT });
  });

  test("getTopic returns NOT_FOUND for unknown topics", async () => {
    const token = oauth.issueToken({
      clientId: "publisher",
      clientSecret: "super-secret",
      scope: "eventbus.pubsub",
    }).access_token;

    await expect(
      getTopicWithToken(token, {
        topic_name: `${topicName}_does_not_exist`,
      }),
    ).rejects.toMatchObject({ code: grpc.status.NOT_FOUND });
  });
});

