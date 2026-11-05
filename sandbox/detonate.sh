#!/bin/sh
# Runs inside the disposable container. Receives the package archive on stdin:
# no host path is ever shared with the code under analysis.
#
# Usage: detonate.sh <npm|pypi> <tar|zip>
set -u
ECOSYSTEM=$1
FORMAT=$2
PHASE_TIMEOUT=${AIRLOCK_PHASE_TIMEOUT:-40}

# --- Decoys: what a developer's home holds, with a per-run canary token -------
CANARY=$AIRLOCK_CANARY
unset AIRLOCK_CANARY
mkdir -p ~/.aws ~/.ssh ~/.config/gh ~/.docker ~/.kube
printf '[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s\n' "$CANARY" "$CANARY" > ~/.aws/credentials
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n' "$CANARY" > ~/.ssh/id_rsa
printf '//registry.npmjs.org/:_authToken=npm_%s\n' "$CANARY" > ~/.npmrc
printf '[pypi]\nusername = __token__\npassword = pypi-%s\n' "$CANARY" > ~/.pypirc
printf 'https://dev:%s@github.com\n' "$CANARY" > ~/.git-credentials
printf 'machine github.com login dev password %s\n' "$CANARY" > ~/.netrc
printf 'github.com:\n    oauth_token: gho_%s\n' "$CANARY" > ~/.config/gh/hosts.yml
printf '{"auths":{"registry.example":{"auth":"%s"}}}\n' "$CANARY" > ~/.docker/config.json
printf 'users:\n- name: dev\n  user:\n    token: %s\n' "$CANARY" > ~/.kube/config
printf '# ~/.bashrc\n' > ~/.bashrc
printf '# ~/.profile\n' > ~/.profile

export AWS_SECRET_ACCESS_KEY="$CANARY" NPM_TOKEN="npm_$CANARY" GITHUB_TOKEN="ghp_$CANARY"
# npm and pip must not touch the decoys themselves, or everything would alert.
export NPM_CONFIG_USERCONFIG=/dev/null NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false
export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_CONFIG_FILE=/dev/null

mkdir -p /work/pkg /work/site
cd /work/pkg || exit 90
cat > /work/archive
if [ "$FORMAT" = zip ]; then
    python3 -m zipfile -e /work/archive /work/pkg || exit 91
else
    tar -xzf /work/archive -C /work/pkg --no-same-owner || exit 91
fi
rm -f /work/archive
ROOT=/work/pkg
[ -d package ] && ROOT=/work/pkg/package
if [ "$ECOSYSTEM" = pypi ] && [ ! -f "$ROOT/setup.py" ] && [ ! -f "$ROOT/pyproject.toml" ]; then
    SUB=$(find /work/pkg -maxdepth 2 \( -name setup.py -o -name pyproject.toml \) -printf '%h\n' | head -1)
    [ -n "$SUB" ] && ROOT=$SUB
fi
cd "$ROOT" || exit 90

# --- Sentinel: tells the host that Falco really sees this container -----------
# Everything Falco reports before this line is the harness, and is ignored.
cat /opt/airlock/sentinel > /dev/null
echo "[airlock] detonation starts"

if [ "$ECOSYSTEM" = npm ]; then
    # Lifecycle scripts run directly: `npm install` would need the dependencies,
    # hence a registry, and a failed resolution would hide the hook entirely.
    for hook in preinstall install postinstall; do
        echo "[airlock] phase: $hook"
        timeout -k 3 "$PHASE_TIMEOUT" npm run --if-present --silent "$hook"
        echo "[airlock] phase $hook exit=$?"
    done
    echo "[airlock] phase: require"
    timeout -k 3 "$PHASE_TIMEOUT" node -e "require(process.cwd())"
    echo "[airlock] phase require exit=$?"
else
    echo "[airlock] phase: install"
    timeout -k 3 "$PHASE_TIMEOUT" python3 -m pip install --no-deps --no-index --no-build-isolation \
        --break-system-packages --target /work/site .
    echo "[airlock] phase install exit=$?"
    echo "[airlock] phase: import"
    timeout -k 3 "$PHASE_TIMEOUT" python3 -c '
import importlib, pkgutil, sys
sys.path.insert(0, "/work/site")
for module in pkgutil.iter_modules(["/work/site"]):
    try:
        importlib.import_module(module.name)
    except BaseException as error:
        print(f"[airlock] import {module.name}: {error!r}")
'
    echo "[airlock] phase import exit=$?"
fi
# Leave time to background processes spawned by the phases above.
sleep "${AIRLOCK_LINGER:-3}"
echo "[airlock] detonation ends"
