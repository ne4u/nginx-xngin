import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stacklib import Stack  # noqa: E402


@pytest.fixture
def stack(tmp_path):
    stacks = []

    def make(**kw):
        s = Stack(str(tmp_path), **kw)
        stacks.append(s)
        return s

    yield make
    for s in stacks:
        s.stop()
