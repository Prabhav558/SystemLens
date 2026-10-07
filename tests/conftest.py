import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from systemlens.config import AgentConfig


@pytest.fixture()
def tmp_home():
    d = Path(tempfile.mkdtemp(prefix="systemlens-test-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture()
def config(tmp_home):
    return AgentConfig(home=tmp_home)
