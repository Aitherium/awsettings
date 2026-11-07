"""The `privacy` domain: search exclusions follow the owner to every machine.

Only the RULES travel (hideGames, hideAdult and the owner's lists). The desk's
temporary !private reveal is never written to disk, so no machine can ever sync
'show everything' to another one.
"""

from __future__ import annotations

from awsettings import core, domains


def test_privacy_is_a_registered_domain():
    dom = domains.get_domain("privacy")
    assert dom.name == "privacy"
    assert dom.locate().name == "search-exclusions.json"


def test_hidden_lists_merge_as_a_union_across_machines():
    dom = domains.get_domain("privacy")
    here = {"hideGames": True, "titles": ["Alpha"], "allow": []}
    there = {"hideGames": True, "titles": ["Beta"], "allow": ["Steam"]}
    merged = core.merge(here, there, domain=dom)
    assert merged["titles"] == ["Alpha", "Beta"]
    assert merged["allow"] == ["Steam"]


def test_only_the_rules_are_synced():
    dom = domains.get_domain("privacy")
    assert dom.synced_keys == {"hideGames", "hideAdult", "folders", "titles", "patterns", "allow"}
    assert dom.strict_inbound is True
