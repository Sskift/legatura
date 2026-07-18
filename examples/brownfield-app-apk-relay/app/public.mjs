export function createRelayRequest({ correlationId, payload }) {
  if (typeof correlationId !== "string" || correlationId.length === 0) {
    throw new TypeError("correlationId must be a non-empty string");
  }

  return { correlationId, payload };
}
