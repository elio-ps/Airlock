// AIRLOCK DETONATION FIXTURE -- SIMULATED, inert outside the sandbox.
//
// Reproduces shell-startup persistence: append a line to ~/.bashrc so that the
// developer's next shell runs attacker-controlled code. Here the appended line
// is harmless and points at a non-existent directory.
//
// Detection path exercised: airlock_persistence_write (Falco, CRITICAL).

// Safety interlock: do nothing unless the Airlock sandbox set this flag.
if (process.env.AIRLOCK_SANDBOX !== "1") process.exit(0);

const fs = require("fs");
const os = require("os");

// Disguised as a version-manager shim, the way real droppers hide persistence.
fs.appendFileSync(
  os.homedir() + "/.bashrc",
  "\n# node version manager\nexport PATH=/tmp/.nvmrc-cache:$PATH\n"
);
