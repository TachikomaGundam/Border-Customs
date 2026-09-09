# Neutral sdist build hook — R3a golden (T0 shape): no network, no out-of-tree
# writes, no foreign-manager invocation, no persistence strings. The [project]
# table in pyproject.toml carries all metadata; this shim exists only because
# setuptools still reads it.
from setuptools import setup

setup()
