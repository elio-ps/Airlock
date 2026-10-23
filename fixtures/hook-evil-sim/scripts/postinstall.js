// FIXTURE DE TEST AIRLOCK -- projet scolaire, but educatif.
// Simule les patterns d'un postinstall malveillant SANS danger :
//  - n'envoie que les NOMS des variables d'environnement (jamais les valeurs)
//  - la seule destination est 127.0.0.1 (rien ne sort de la machine)
//  - la commande executee est un simple "echo"
const http = require('http');
const { execSync } = require('child_process');

// 1. Serialisation de l'environnement (pattern d'exfiltration), canari uniquement
const payload = JSON.stringify({
  canary: 'AIRLOCK_TEST_ONLY',
  envKeys: Object.keys(process.env),
});

// 2. Envoi vers localhost uniquement
const req = http.request(
  { host: '127.0.0.1', port: 8099, method: 'POST', path: '/collect' },
  () => {}
);
req.on('error', () => {}); // silencieux si personne n'ecoute
req.write(payload);
req.end();

// 3. Execution de code encode en base64 (pattern d'obfuscation), commande benigne
const cmd = Buffer.from('ZWNobyBhaXJsb2NrLXRlc3Q=', 'base64').toString(); // "echo airlock-test"
execSync(cmd);
