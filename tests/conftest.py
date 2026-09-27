"""Import the package FROM THE TREE, the awmine/tests idiom.

Without this the suite needs `pip install -e` before it can even be collected, and
the hermetic CI gate installs nothing -- so the whole directory errored at conftest
import and ran nowhere (CGT001, measured 2026-09-22).
"""
import sys as _sys
from pathlib import Path as _Path

import pytest as _pytest

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

#: Anything on the developer's machine that would point a test at a REAL hub. A
#: `~/.awsettings/config.json` with a url + token_command turned every CLI test
#: into a request to the live store (and a DEAD when signed out).
_HOST_ENV = ("AWSETTINGS_URL", "AITHER_PORTAL_URL", "AITHER_ELYSIUM_URL",
             "AWSETTINGS_TOKEN", "AWSETTINGS_TOKEN_FILE", "AWSETTINGS_TOKEN_COMMAND",
             "AWSETTINGS_SIGN", "AWSETTINGS_REQUIRE_SEAL", "AWSETTINGS_KEYS_URL",
             "AWSETTINGS_PROJECT", "AITHER_PORTAL_TOKEN", "AITHER_SYNC_TOKEN")


@_pytest.fixture(autouse=True)
def _isolated_awsettings_home(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("awsettings-home")
    monkeypatch.setenv("AWSETTINGS_HOME", str(home))
    for var in _HOST_ENV:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWSETTINGS_LOCAL", "1")
    # The push debounce stamp is computed at import from the REAL home; a test push
    # must not touch the developer's own hook state.
    from awsettings import cli as _cli
    monkeypatch.setattr(_cli, "DEBOUNCE_STAMP", home / "last-push")
