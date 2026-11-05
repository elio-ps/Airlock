// AIRLOCK DETONATION FIXTURE -- benign.
//
// A legitimate build step: compiles nothing dangerous, writes only inside the
// package's own tree, touches no secret and opens no connection. Represents the
// many packages whose install hook is a real but harmless build.
//
// Expected: no detonation finding -> ALLOW once detonated clean.

const fs = require("fs");
const path = require("path");

const outDir = path.join(__dirname, "dist");
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "bundle.js"), "module.exports = 42;\n");
console.log("build: wrote dist/bundle.js");
