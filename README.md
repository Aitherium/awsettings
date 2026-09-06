# awsettings

**Your agent's permissions and config, following you to the next machine.**

```bash
pip install git+https://github.com/Aitherium/awsettings.git
awsettings hook install     # and never think about it again
```

<sub>Installed from git until the first PyPI release — `pip install awsettings` is
not live yet, and advertising an install that 404s is worse than a longer one.
This line goes when the release does.</sub>

Your coding agent keeps its permission allowlist, its enabled tool servers and its
hooks in a local file. Open a session on a second machine — a laptop, a shell on a
server, a dev container your phone just spun up — and none of it is there.

So you approve the same action again. By hand. Once per surface. Forever. And the
copies drift apart while every one of them looks perfectly correct.

## What you get

```
$ awsettings status
local:  /home/you/project/.claude/settings.local.json (present)
remote: file:/home/you/.awsettings/profile.json
hooks:  PostToolUse, SessionStart
a pull would apply 2 change(s):
  + permissions.allow: Bash(python tools/deploy.py:*)
  + enabledMcpjsonServers: my-server
```

```
$ awsettings pull
applied 2 change(s) to /home/you/project/.claude/settings.local.json:
  + permissions.allow: Bash(python tools/deploy.py:*)
  + enabledMcpjsonServers: my-server
```

## Three rules it will not break

**Credentials never travel** — and they are dropped by *name*, not by inspecting
the value. A "does this look like a token" heuristic passes every secret that does
not look like one, and that failure is invisible until the secret is already
published. `env`, `apiKeyHelper`, `awsCredentialExport`, `sandbox.credentials` and
their kin stay on the machine they were typed on. `awsettings push --dry-run`
prints exactly what would leave.

**Arrays union; they are never replaced.** Two machines both edit this file. With
replace semantics, machine B silently loses the rule machine A never had — and
neither of them can tell. Every list here merges.

**A deny is one-way.** A sync may *add* a deny or ask rule. It may never drop one.
A lost allow rule costs you a prompt; a lost deny rule costs you the thing the deny
existed to prevent, quietly, on a machine whose owner still believes it is there.
If you genuinely want to remove one everywhere, `--prune-denies` says so out loud.

## It writes the personal file, not the shared one

Only `.claude/settings.local.json` — gitignored, yours. Never the committed
`.claude/settings.json`, because syncing your permission allowlist into a file
your team reviews as policy hands everyone rules they never approved.

## Autonomy is a hook, not a daemon

```bash
awsettings hook install
```

* **SessionStart → pull.** A new machine is stale before its first tool call, so
  that is when it catches up.
* **A settings write → push**, debounced. A rule you approve here is on its way to
  the others before you have finished the thought.

No background process. A daemon is a second thing to keep alive on every surface
this exists to stop hand-maintaining — and when it dies, it dies quietly, which is
the same failure as the drift it was meant to fix. Both hooks end in `|| true`:
a settings sync must never be able to fail a session open, because offline is the
normal state of a laptop and the correct behaviour offline is to carry on.

## Where the profile lives

No account required. The default is a plain JSON file in a folder you already sync
— a git repo, a drive folder, a USB stick:

```bash
export AWSETTINGS_PROFILE=~/Dropbox/awsettings.json
```

Or point it at any endpoint that serves a JSON object on `GET` and merges one on
`PUT`:

```bash
export AWSETTINGS_URL=https://example.com/api/settings/preferences
export AWSETTINGS_TOKEN=...     # environment only — never a command-line flag,
                                # which lands in shell history and the process list
```

A transport failure is never read as "no settings": both backends raise, and the
CLI exits **2** rather than merging nothing and reporting success.

## Exit codes

| code | meaning |
|---|---|
| 0 | did the thing (or there was nothing to do — it says which) |
| 1 | a rule refused it |
| 2 | could not judge: profile unreachable, or a settings file would not parse |

## Prove it before you trust it

```bash
awsettings --self-test
```

Runs offline. Asserts that credentials neither leave nor arrive, that arrays union
instead of replacing, that a deny is never dropped by default, that installing the
hooks twice leaves one hook and does not clobber somebody else's, that a malformed
settings file refuses rather than reading as empty, and that writes are atomic.

## Licence

Apache-2.0.
