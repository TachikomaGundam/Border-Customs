"""W2.4b benign wheel control: zero-dependency, pure-Python wheel (rt_benign_local).

Built directly as a zip to keep the fixture reproducible and dependency-free;
carries the PEP 427 quartet (__init__ + METADATA + WHEEL + RECORD)."""
__version__ = "1.0.0"


def marker():
    return "rt-benign-local"
