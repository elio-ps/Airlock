// AIRLOCK DETONATION FIXTURE -- benign.
// A pure library with no install hook. The require phase runs only plain
// computation, so a clean detonation confirms "loading it is safe".
// Expected: no detonation finding -> ALLOW.
function fib(n) {
  let [a, b] = [0, 1];
  for (let i = 0; i < n; i += 1) [a, b] = [b, a + b];
  return a;
}
module.exports = { fib };
