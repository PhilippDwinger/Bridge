// Bridge 4 for JavaScript (Node ≥ 20 and modern browsers, docs/10 §2): join a network, send and receive end-to-end
// encrypted, tasks, agents, connected networks. Same formats and checks as the Rust core; crypto only through the
// embedded, reviewed noble libraries (vendor/noble.js).

export { Agent } from './src/agent.js';
export { Client, Received, agentOfStatement, checkFederation, gatewayInLog } from './src/client.js';
export { Content } from './src/content.js';
export { Envelope } from './src/envelope.js';
export { BridgeError, NodeError, Untrusted } from './src/errors.js';
export { canonical, canonicalText, parseStrict } from './src/json.js';
export { Identity, KeyCard } from './src/keys.js';
export { JoinLink } from './src/link.js';
export { Puzzle } from './src/pow.js';
export { SignedRequest } from './src/request.js';
export { Statement } from './src/statement.js';
export { b64, b64Var, base32 } from './src/encoding.js';
