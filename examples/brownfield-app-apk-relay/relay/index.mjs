export function createRelay({ deliver }) {
  if (typeof deliver !== "function") {
    throw new TypeError("deliver must be a function");
  }

  return async function relay(request) {
    if (!request || typeof request !== "object" || Array.isArray(request)) {
      throw new TypeError("request must be an object");
    }
    if (typeof request.correlationId !== "string" || request.correlationId.length === 0) {
      throw new TypeError("request.correlationId must be a non-empty string");
    }

    const delivery = await deliver({
      correlationId: request.correlationId,
      payload: request.payload
    });

    return {
      correlationId: request.correlationId,
      accepted: delivery?.accepted === true
    };
  };
}
