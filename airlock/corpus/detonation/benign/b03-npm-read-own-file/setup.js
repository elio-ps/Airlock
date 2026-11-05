// AIRLOCK DETONATION FIXTURE -- benign.
//
// Reads a configuration file that ships INSIDE the package. Reading your own
// files is normal; the sandbox only flags reads of the decoy secrets it plants.
//
// Expected: no detonation finding -> ALLOW once detonated clean.

const fs = require("fs");
const path = require("path");

const config = JSON.parse(fs.readFileSync(path.join(__dirname, "config.json"), "utf8"));
console.log(`setup: using preset "${config.preset}"`);
