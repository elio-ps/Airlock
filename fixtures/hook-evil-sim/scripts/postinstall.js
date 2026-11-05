// AIRLOCK TEST FIXTURE -- school project, educational purpose.
// Simulates the patterns of a malicious postinstall WITHOUT any danger:
//  - only sends the NAMES of environment variables (never their values)
//  - the only destination is 127.0.0.1 (nothing leaves the machine)
//  - the executed command is a plain "echo"
const http = require('http');
const { execSync } = require('child_process');

// 1. Environment serialization (exfiltration pattern), canary only
const payload = JSON.stringify({
  canary: 'AIRLOCK_TEST_ONLY',
  envKeys: Object.keys(process.env),
});

// 2. Send to localhost only
const req = http.request(
  { host: '127.0.0.1', port: 8099, method: 'POST', path: '/collect' },
  () => {}
);
req.on('error', () => {}); // silent when nobody is listening
req.write(payload);
req.end();

// 3. Run base64-encoded code (obfuscation pattern), benign command
const cmd = Buffer.from('ZWNobyBhaXJsb2NrLXRlc3Q=', 'base64').toString(); // "echo airlock-test"
execSync(cmd);
