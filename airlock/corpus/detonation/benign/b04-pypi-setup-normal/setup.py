# AIRLOCK DETONATION FIXTURE -- benign.
# A normal setup.py: it reads only its own README to fill the long description.
# Reading your own shipped files is routine; no secret, no network.
# Expected: no detonation finding -> ALLOW once detonated clean.
import os

from setuptools import setup

here = os.path.dirname(__file__)
with open(os.path.join(here, "README.md"), encoding="utf-8") as readme:
    long_description = readme.read()

setup(
    name="airlock-benign-setup",
    version="1.0.0",
    description="Airlock benign fixture",
    long_description=long_description,
    packages=["simclean"],
)
