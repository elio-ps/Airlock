// AIRLOCK DETONATION FIXTURE -- benign.
//
// Connects to 127.0.0.1 only, like a tool checking a local dev server. The
// outbound rule excludes loopback, so this must NOT be flagged: it guards
// against a sandbox that would treat any connect() as suspicious.
//
// Expected: no detonation finding -> ALLOW once detonated clean.

const net = require("net");

const socket = net.connect(3000, "127.0.0.1");
socket.setTimeout(1000);
socket.on("error", () => {}); // nothing listening locally: that is fine
socket.on("timeout", () => socket.destroy());
socket.on("connect", () => socket.end());
