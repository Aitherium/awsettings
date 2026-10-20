"""A push hook folded into hookd's http hook counts as installed; install adds no copy."""
from awsettings import hooks

URL = ("http://127.0.0.1:8369/run?t=20&h=ep%3Aawsettings.cli%3Amain%7C--quiet%7Cpush"
       "%7C--debounce")


def _routed_settings():
    return {"hooks": {"PostToolUse": [{"hooks": [{"type": "http", "url": URL}]}]}}


def test_install_does_not_duplicate_a_routed_push():
    out = hooks.plan(_routed_settings())
    post = out["hooks"]["PostToolUse"]
    assert len(post) == 1 and post[0]["hooks"][0]["type"] == "http"
    # SessionStart is never folded (http hooks are not accepted there): still installed.
    assert any(hooks._is_ours(g) for g in out["hooks"]["SessionStart"])


def test_routed_push_reports_installed():
    assert hooks.installed(_routed_settings()) == ["PostToolUse"]


def test_plain_settings_still_get_both_hooks():
    out = hooks.plan({})
    assert hooks.installed(out) == ["PostToolUse", "SessionStart"]
