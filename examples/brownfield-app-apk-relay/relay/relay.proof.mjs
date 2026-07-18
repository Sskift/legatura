import assert from "node:assert/strict";
import test from "node:test";

import { createRelay } from "./index.mjs";

test("relay preserves the request correlation id through delivery", async () => {
  const delivered = [];
  const relay = createRelay({
    deliver: async (envelope) => {
      delivered.push(envelope);
      return { accepted: true };
    }
  });

  const result = await relay({
    correlationId: "brownfield-correlation-1",
    payload: { artifact: "app.apk" }
  });

  assert.deepEqual(delivered, [{
    correlationId: "brownfield-correlation-1",
    payload: { artifact: "app.apk" }
  }]);
  assert.deepEqual(result, {
    correlationId: "brownfield-correlation-1",
    accepted: true
  });
});
