"""awsettings — your agent's permissions and config, following you to the next machine.

An agent harness keeps its permission allowlist, enabled tool servers and hooks in
a local file. Work from a second machine and none of it is there: you re-approve
the same action, by hand, once per surface, forever, while the copies drift apart
and every one of them looks correct.

    awsettings status
    awsettings pull
    awsettings push
    awsettings hook install
"""
__version__ = "0.1.0"

__all__ = ["__version__"]
