// Errors of the Bridge 4 SDK (codes as in docs/04 §9).

export class BridgeError extends Error {
  constructor(code, message = '') {
    super(message ? `${code}: ${message}` : code);
    this.code = code;
    this.detail = message;
  }
}

/** The node answered with an error (`code`, `retryAfter` in seconds or null, HTTP `status`). */
export class NodeError extends BridgeError {
  constructor(code, message = '', retryAfter = null, status = 0) {
    super(code, message);
    this.retryAfter = retryAfter;
    this.status = status;
  }
}

/** The node is not who it should be, or answered nonsense. */
export class Untrusted extends BridgeError {
  constructor(message) {
    super('UNTRUSTED', message);
  }
}

export const badFormat = (message) => new BridgeError('BAD_FORMAT', message);
export const badSignature = () => new BridgeError('BAD_SIGNATURE');
