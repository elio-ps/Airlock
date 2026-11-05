// AIRLOCK DETONATION FIXTURE -- SIMULATED, inert outside the sandbox.
//
// Reproduces a dropper: write a second-stage script to a world-writable
// directory and execute it, as compromised packages did to pull in
// cryptominers. The dropped stage here only prints a line.
//
// Detection path exercised: airlock_exec_from_writable_dir (Falco, CRITICAL).

// Safety interlock: do nothing unless the Airlock sandbox set this flag.
if (process.env.AIRLOCK_SANDBOX !== "1") process.exit(0);

const fs = require("fs");
const cp = require("child_process");

const stage = "/tmp/.cache-update"; // a writable path outside the package tree
fs.writeFileSync(stage, "#!/bin/sh\necho 'second stage running'\n");
fs.chmodSync(stage, 0o755);
cp.spawnSync(stage, { stdio: "inherit" });
