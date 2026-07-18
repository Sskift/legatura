export function createDeliveryPort(deliver) {
  if (typeof deliver !== "function") {
    throw new TypeError("deliver must be a function");
  }

  return async function deliveryPort(envelope) {
    return deliver(envelope);
  };
}
