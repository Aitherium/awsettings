"""``awsettings network`` -- wired NIC power saving off, and a gateway latency probe.

    awsettings network show                  the intent and where it lives
    awsettings network check [--json] [--count N] [--no-probe]
    awsettings network apply [--dry-run]

THE SYMPTOM THIS EXISTS FOR. A desktop on a wired gigabit-or-better link pings its own
router at 10-160 ms (avg tens of ms) with ZERO packet errors on the NIC. Nothing is
broken in the counters, so nothing looks wrong -- the NIC is napping. Energy-Efficient
Ethernet (802.3az) and the vendor extras on top of it (Green Ethernet, Advanced EEE,
Power Saving Mode, Gigabit Lite) put the link into low-power idle between packets, and
each wake costs latency. On a box that is on AC all day the saving is a few hundred
milliwatts; the cost is every interactive round trip. Turning them off took one
measured desktop from avg 50 ms / max 159 ms to avg 3 ms to its router.

WHAT IT TOUCHES. Physical WIRED adapters only (802.3 medium, not virtual, not a VPN or
tunnel). Wi-Fi power saving is a different trade (battery, roaming) and is never read or
written here, whatever the driver calls its property. On a wired adapter only an on/off
property whose name is in ``POWER_SAVING_NAMES`` is touched, and only toward its
"disabled" value -- this never ENABLES anything, and a property whose values are not a
switch (``EEE Max Support Speed``) is left alone.

ELEVATION. Changing an adapter property needs an administrator token. A non-elevated
``Set-NetAdapterAdvancedProperty`` fails with "System Error 5"; ``sudo`` may be disabled
on the box. So ``apply`` writes its plan to a file and, when not admin, runs ONE elevated
PowerShell via ``Start-Process -Verb RunAs`` (one UAC prompt for every change), which
writes a result file this process reads back -- an elevated child's stdout is not ours
to read. Then it re-reads the adapters and judges again: the verdict is the re-check,
never the child's say-so. On Linux it is one ``sudo`` for every ``ethtool --set-eee``.

Changing a NIC property restarts that NIC: the link drops for a few seconds, once per
adapter (every property is set with ``-NoRestart`` and the adapter restarted once).

EXIT CODES. 0 ok · 1 drift (or a high-latency wired link) · 2 could not judge --
PowerShell/ethtool missing, no wired adapter, every ping lost, the UAC prompt declined.
Never 0 for "I could not look".
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from .domains import network_intent_path
from .store import CouldNotRunError, read_json

#: (rc, stdout, stderr) for argv, with a timeout in seconds.
Runner = Callable[..., "tuple[int, str, str]"]

DEFAULT_LATENCY_MAX_MS = 5.0
DEFAULT_COUNT = 10
MODES = ("off", "unmanaged")

#: The power-saving switches, by DisplayName, across vendors. Realtek: Energy-Efficient
#: Ethernet, Advanced EEE, Green Ethernet, Gigabit Lite, Power Saving Mode. Intel
#: (I219/I225/I226): Energy Efficient Ethernet. Anchored: "EEE Max Support Speed" must
#: not match.
POWER_SAVING_NAMES = re.compile(
    r"^\s*(energy[- ]?efficient[- ]ethernet|advanced eee|eee|green ethernet|"
    r"gigabit lite|power saving mode)\s*$", re.IGNORECASE)
#: The standard keyword for EEE, matched too, whatever a driver names it in the UI.
POWER_SAVING_KEYWORDS = frozenset({"*eee"})
#: The "switch is off" spellings, in preference order.
OFF_VALUES = ("Disabled", "Off", "Disable")
#: Descriptions that are never a physical wired NIC, even when Windows says 802.3.
VIRTUAL_DESC = re.compile(
    r"hyper-v|virtual|vpn|tap-|tap adapter|wireguard|tunnel|loopback|wan miniport|"
    r"vmware|virtualbox|zerotier|tailscale|npcap|bluetooth|wi-?fi|wireless|802\.11",
    re.IGNORECASE)
#: Linux names that are never a physical wired NIC.
LINUX_VIRTUAL_NAME = re.compile(
    r"^(lo|veth|docker|br-|br\d|virbr|vnet|tap|tun|wg|zt|tailscale|cni|flannel|cali|"
    r"podman|vxlan|bond|team|dummy|ifb|sit|gre|ip6tnl)")
_SAFE_IFNAME = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")

#: NdisPhysicalMedium 14 = 802.3 (wired Ethernet). 9 = Native 802.11, 10 = Bluetooth.
NDIS_802_3 = 14
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


# --- intent ------------------------------------------------------------------------


@dataclass
class Intent:
    """What THIS machine should look like. Built from the domain file."""

    wired_power_saving: str = "off"
    latency_max_ms: float = DEFAULT_LATENCY_MAX_MS
    adapters: dict = field(default_factory=dict)
    source: str = "default"

    def mode_for(self, adapter: str) -> str:
        return self.adapters.get(adapter, self.wired_power_saving)


def load_intent(path: Path | None = None) -> Intent:
    """The intent at ``path`` (default: the domain file). Absent = power saving off.

    A value this cannot interpret RAISES: guessing "off" for a typo would rewrite NICs
    the owner asked to leave alone, guessing "unmanaged" would report ok on silence.
    """
    target = Path(path) if path is not None else network_intent_path()
    data = read_json(target)
    if not data:
        return Intent(source="default")
    mode = str(data.get("wired_power_saving", "off")).strip().lower()
    if mode not in MODES:
        raise CouldNotRunError(f"{target}: wired_power_saving={mode!r}; want one of {MODES}")
    try:
        latency = float(data.get("latency_max_ms", DEFAULT_LATENCY_MAX_MS))
    except (TypeError, ValueError) as exc:
        raise CouldNotRunError(f"{target}: latency_max_ms is not a number") from exc
    adapters = data.get("adapters") or {}
    if not isinstance(adapters, dict):
        raise CouldNotRunError(f"{target}: adapters must be an object")
    clean: dict = {}
    for name, val in adapters.items():
        v = str(val.get("power_saving") if isinstance(val, dict) else val).strip().lower()
        if v not in MODES:
            raise CouldNotRunError(f"{target}: adapters[{name!r}]={v!r}; want one of {MODES}")
        clean[str(name)] = v
    return Intent(wired_power_saving=mode, latency_max_ms=latency, adapters=clean,
                  source=str(target))


# --- shapes ------------------------------------------------------------------------


@dataclass
class Prop:
    display_name: str
    value: str
    keyword: str = ""
    valid: list = field(default_factory=list)


@dataclass
class Adapter:
    name: str
    description: str = ""
    status: str = ""
    link_speed: str = ""
    if_index: int | None = None
    props: list = field(default_factory=list)


@dataclass
class Inventory:
    adapters: list = field(default_factory=list)
    #: (gateway, adapter name, source address) of the preferred wired default route.
    gateway: tuple | None = None


@dataclass
class Finding:
    adapter: str
    setting: str
    current: str
    want: str
    ok: bool


@dataclass
class PingStats:
    sent: int = 0
    received: int = 0
    avg_ms: float | None = None
    max_ms: float | None = None


@dataclass
class Report:
    exit_code: int
    lines: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    latency: dict | None = None
    unjudged: list = field(default_factory=list)

    def as_json(self) -> dict:
        return {"exit_code": self.exit_code, "findings": [asdict(f) for f in self.findings],
                "latency": self.latency, "unjudged": self.unjudged}


# --- runners ------------------------------------------------------------------------


def _default_runner(cmd: list, timeout: float = 60.0) -> tuple:
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, check=False,
                              creationflags=_NO_WINDOW)
    except FileNotFoundError:
        return (127, "", f"{cmd[0]}: not found")
    except (OSError, subprocess.SubprocessError) as exc:
        return (126, "", f"{cmd[0]}: {exc}")
    return (done.returncode, done.stdout or "", done.stderr or "")


def _platform() -> str:
    return sys.platform


def _is_admin() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def _state_dir() -> Path:
    return Path.home() / ".aither" / "network"


def _run(runner: Runner, cmd: list, timeout: float = 60.0) -> tuple:
    return runner(cmd, timeout=timeout)


# --- windows -------------------------------------------------------------------------

_PS = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
       "-Command"]

#: One read: physical adapters + their advanced properties + IPv4 default routes.
_WIN_INVENTORY = r"""
$ErrorActionPreference = 'Stop'
$ad = @()
foreach ($a in @(Get-NetAdapter -Physical)) {
  $p = @(Get-NetAdapterAdvancedProperty -Name $a.Name -ErrorAction SilentlyContinue |
         Select-Object DisplayName, DisplayValue, RegistryKeyword, ValidDisplayValues)
  $ad += [pscustomobject]@{ Name = $a.Name; InterfaceDescription = $a.InterfaceDescription;
    NdisPhysicalMedium = [int]$a.NdisPhysicalMedium; Virtual = [bool]$a.Virtual;
    Status = [string]$a.Status; LinkSpeed = [string]$a.LinkSpeed; ifIndex = [int]$a.ifIndex;
    Properties = $p }
}
$r = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
         -ErrorAction SilentlyContinue |
       Select-Object ifIndex, NextHop, RouteMetric, InterfaceMetric)
$i = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
       Select-Object ifIndex, IPAddress)
$sw = @(); $vn = @()
try {
  $sw = @(Get-VMSwitch -SwitchType External -ErrorAction Stop |
          Select-Object Name, NetAdapterInterfaceDescription)
  $vn = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Name -like 'vEthernet (*' } |
          Select-Object Name, ifIndex)
} catch { }
ConvertTo-Json -Depth 5 -Compress -InputObject ([pscustomobject]@{
  adapters = $ad; routes = $r; addresses = $i; switches = $sw; vnics = $vn })
"""

#: The apply script. Reads a plan file, writes a result file. Run elevated or not.
_WIN_APPLY = r"""
param([string]$PlanPath, [string]$ResultPath)
$errs = @(); $applied = 0; $touched = @{}
try {
  $plan = Get-Content -Raw -LiteralPath $PlanPath | ConvertFrom-Json
  foreach ($c in @($plan.changes)) {
    try {
      Set-NetAdapterAdvancedProperty -Name $c.adapter -DisplayName $c.display_name `
        -DisplayValue $c.value -NoRestart -ErrorAction Stop
      $applied++; $touched[$c.adapter] = $true
    } catch { $errs += ("{0} / {1}: {2}" -f $c.adapter, $c.display_name, $_.Exception.Message) }
  }
  foreach ($n in $touched.Keys) {
    try { Restart-NetAdapter -Name $n -Confirm:$false -ErrorAction Stop }
    catch { $errs += ("restart {0}: {1}" -f $n, $_.Exception.Message) }
  }
} catch { $errs += $_.Exception.Message }
$code = 0; if ($errs.Count -gt 0) { $code = 1 }
ConvertTo-Json -Depth 3 -InputObject ([pscustomobject]@{
  exit_code = $code; applied = $applied; errors = @($errs) }) |
  Set-Content -LiteralPath $ResultPath -Encoding UTF8
exit $code
"""


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def is_wired_physical(rec: dict) -> bool:
    """A record from ``Get-NetAdapter -Physical``: 802.3, not virtual, not a tunnel."""
    try:
        medium = int(rec.get("NdisPhysicalMedium", -1))
    except (TypeError, ValueError):
        return False
    if medium != NDIS_802_3 or rec.get("Virtual"):
        return False
    return not VIRTUAL_DESC.search(str(rec.get("InterfaceDescription") or "")
                                   + " " + str(rec.get("Name") or ""))


def parse_windows_inventory(text: str) -> Inventory:
    """The inventory JSON -> wired adapters + the preferred wired default route."""
    try:
        raw = json.loads(text.strip().lstrip("﻿") or "{}")
    except json.JSONDecodeError as exc:
        raise CouldNotRunError(f"adapter inventory is not JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise CouldNotRunError("adapter inventory is not an object")
    adapters = []
    for rec in _as_list(raw.get("adapters")):
        if not isinstance(rec, dict) or not is_wired_physical(rec):
            continue
        props = [Prop(display_name=str(p.get("DisplayName") or ""),
                      value=str(p.get("DisplayValue") or ""),
                      keyword=str(p.get("RegistryKeyword") or ""),
                      valid=[str(v) for v in _as_list(p.get("ValidDisplayValues"))])
                 for p in _as_list(rec.get("Properties")) if isinstance(p, dict)]
        idx = rec.get("ifIndex")
        adapters.append(Adapter(name=str(rec.get("Name") or ""),
                                description=str(rec.get("InterfaceDescription") or ""),
                                status=str(rec.get("Status") or ""),
                                link_speed=str(rec.get("LinkSpeed") or ""),
                                if_index=int(idx) if isinstance(idx, int) else None,
                                props=props))
    # route-capable interfaces: ifIndex -> label. A wired NIC, or the host vNIC of a
    # Hyper-V EXTERNAL switch bound to one -- on such a host the default route lives on
    # "vEthernet (<switch>)" and the physical NIC carries no IP at all.
    by_index = {a.if_index: a.name for a in adapters if a.if_index is not None}
    wired_desc = {a.description: a.name for a in adapters}
    vnic_index = {str(v.get("Name") or ""): v.get("ifIndex")
                  for v in _as_list(raw.get("vnics")) if isinstance(v, dict)}
    for sw in _as_list(raw.get("switches")):
        if not isinstance(sw, dict):
            continue
        nic = wired_desc.get(str(sw.get("NetAdapterInterfaceDescription") or ""))
        idx = vnic_index.get(f"vEthernet ({sw.get('Name')})")
        if nic and isinstance(idx, int):
            by_index.setdefault(idx, f"vEthernet ({sw.get('Name')}) -> {nic}")
    addrs: dict = {}
    for rec in _as_list(raw.get("addresses")):
        if isinstance(rec, dict) and rec.get("ifIndex") in by_index:
            addrs.setdefault(rec["ifIndex"], str(rec.get("IPAddress") or ""))
    best = None
    for rec in _as_list(raw.get("routes")):
        if not isinstance(rec, dict) or rec.get("ifIndex") not in by_index:
            continue
        hop = str(rec.get("NextHop") or "")
        if not hop or hop == "0.0.0.0":
            continue
        metric = int(rec.get("RouteMetric") or 0) + int(rec.get("InterfaceMetric") or 0)
        if best is None or metric < best[0]:
            best = (metric, hop, by_index[rec["ifIndex"]], addrs.get(rec["ifIndex"], ""))
    return Inventory(adapters=adapters, gateway=best[1:] if best else None)


def off_value(valid: list) -> str | None:
    """The value that turns a switch OFF, or None when the property is not a switch."""
    lowered = {v.lower(): v for v in valid}
    for cand in OFF_VALUES:
        if cand.lower() in lowered:
            return lowered[cand.lower()]
    return None


def power_findings(adapters: list, intent: Intent) -> list:
    """One finding per power-saving switch on every managed wired adapter."""
    out = []
    for a in adapters:
        if intent.mode_for(a.name) != "off":
            continue
        for p in a.props:
            if not (POWER_SAVING_NAMES.match(p.display_name)
                    or p.keyword.lower() in POWER_SAVING_KEYWORDS):
                continue
            want = off_value(p.valid)
            if want is None:
                continue
            out.append(Finding(adapter=a.name, setting=p.display_name, current=p.value,
                               want=want, ok=p.value.strip().lower() == want.lower()))
    return out


def _windows_inventory(runner: Runner) -> Inventory:
    rc, out, err = _run(runner, _PS + [_WIN_INVENTORY], timeout=90)
    if rc != 0:
        raise CouldNotRunError(f"adapter inventory failed (rc {rc}): {(err or out).strip()[:300]}")
    return parse_windows_inventory(out)


def _ps_quote(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _windows_apply(changes: list, runner: Runner, is_admin: Callable, state_dir: Path) -> tuple:
    """Run the plan, elevated once if needed. (rc, message)."""
    state_dir.mkdir(parents=True, exist_ok=True)
    script = state_dir / "apply-network.ps1"
    plan = state_dir / "apply-plan.json"
    result = state_dir / "last-apply.json"
    script.write_text(_WIN_APPLY, encoding="utf-8-sig")
    plan.write_text(json.dumps({"changes": [asdict(c) for c in changes]}, indent=2),
                    encoding="utf-8")
    if result.exists():
        result.unlink()
    file_args = ["-File", str(script), "-PlanPath", str(plan), "-ResultPath", str(result)]
    if is_admin():
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               *file_args]
    else:
        # Start-Process does not quote ArgumentList elements: embed the quotes ourselves.
        arglist = ("'-NoProfile -ExecutionPolicy Bypass -File \"{0}\" -PlanPath \"{1}\" "
                   "-ResultPath \"{2}\"'").format(script, plan, result)
        cmd = _PS + [f"$p = Start-Process powershell -Verb RunAs -Wait -PassThru "
                     f"-WindowStyle Hidden -ArgumentList {arglist}; exit $p.ExitCode"]
    rc, out, err = _run(runner, cmd, timeout=300)
    if not result.is_file():
        why = (err or out).strip()[:300] or f"rc {rc}"
        return (2, f"no result file from the {'elevated ' if not is_admin() else ''}apply "
                   f"(UAC declined or the child died): {why}")
    try:
        res = json.loads(result.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return (2, f"unreadable result file {result}: {exc}")
    errs = _as_list(res.get("errors"))
    if errs:
        return (1, "apply reported: " + "; ".join(str(e) for e in errs))
    return (0, f"applied {res.get('applied', 0)} change(s)")


# --- linux ---------------------------------------------------------------------------


def linux_wired_interfaces(sys_net: Path = Path("/sys/class/net")) -> list:
    """Physical Ethernet interfaces: a backing device, type 1, no wireless, not virtual."""
    out = []
    try:
        entries = sorted(sys_net.iterdir())
    except OSError:
        return out
    for d in entries:
        name = d.name
        if LINUX_VIRTUAL_NAME.match(name) or not _SAFE_IFNAME.match(name):
            continue
        if not (d / "device").exists():
            continue
        if (d / "wireless").exists() or (d / "phy80211").exists():
            continue
        try:
            if (d / "type").read_text().strip() != "1":
                continue
        except OSError:
            continue
        out.append(name)
    return out


def parse_ethtool_eee(text: str, rc: int) -> str | None:
    """``ethtool --show-eee`` -> enabled | disabled | unsupported | None (unparseable)."""
    m = re.search(r"EEE status:\s*([^\n]+)", text or "", re.IGNORECASE)
    if m:
        status = m.group(1).strip().lower()
        if status.startswith("enabled"):
            return "enabled"
        if status.startswith("disabled"):
            return "disabled"
        if "not supported" in status:
            return "unsupported"
    if rc != 0:
        return "unsupported"
    return None


def parse_linux_default_routes(text: str) -> list:
    """``ip -4 route show default`` -> [(gateway, dev, metric)]."""
    out = []
    for line in (text or "").splitlines():
        gw = re.search(r"\bvia\s+(\S+)", line)
        dev = re.search(r"\bdev\s+(\S+)", line)
        if not (line.strip().startswith("default") and gw and dev):
            continue
        met = re.search(r"\bmetric\s+(\d+)", line)
        out.append((gw.group(1), dev.group(1), int(met.group(1)) if met else 0))
    return out


def _linux_findings(intent: Intent, runner: Runner, sys_net: Path, unjudged: list) -> tuple:
    wired = linux_wired_interfaces(sys_net)
    findings = []
    for name in wired:
        if intent.mode_for(name) != "off":
            continue
        rc, out, err = _run(runner, ["ethtool", "--show-eee", name], timeout=15)
        if rc == 127:
            raise CouldNotRunError("ethtool is not installed")
        state = parse_ethtool_eee(out + err, rc)
        if state is None:
            unjudged.append(f"{name}: unreadable ethtool output")
        elif state != "unsupported":
            findings.append(Finding(adapter=name, setting="EEE", current=state,
                                    want="disabled", ok=state == "disabled"))
    return wired, findings


# --- ping ------------------------------------------------------------------------------

_REPLY = re.compile(r"time\s*([=<])\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)


def parse_ping(text: str, sent: int | None = None) -> PingStats:
    """Reply lines of Windows or Linux ``ping``. ``time<1ms`` counts as 0.5 ms."""
    times = []
    for line in (text or "").splitlines():
        if "ttl=" not in line.lower():
            continue          # skips the summary block, whose numbers are not replies
        m = _REPLY.search(line)
        if m:
            times.append(0.5 if m.group(1) == "<" else float(m.group(2)))
    if sent is None:
        m = re.search(r"Sent = (\d+)", text or "") or re.search(
            r"(\d+) packets transmitted", text or "")
        sent = int(m.group(1)) if m else len(times)
    return PingStats(sent=sent, received=len(times),
                     avg_ms=(sum(times) / len(times)) if times else None,
                     max_ms=max(times) if times else None)


def _ping(platform: str, gateway: str, source: str, dev: str, count: int,
          runner: Runner) -> PingStats:
    if platform == "win32":
        cmd = ["ping", "-n", str(count), "-w", "1000"]
        if source:
            cmd += ["-S", source]
    else:
        cmd = ["ping", "-c", str(count), "-W", "1", "-i", "0.2"]
        if dev:
            cmd += ["-I", dev]
    rc, out, err = _run(runner, cmd + [gateway], timeout=count * 2 + 10)
    if rc == 127:
        raise CouldNotRunError("ping is not installed")
    return parse_ping(out, sent=count)


# --- check / apply ----------------------------------------------------------------------


def _collect(intent: Intent, platform: str, runner: Runner, sys_net: Path,
             unjudged: list) -> tuple:
    """(wired adapter names, findings, (gateway, dev, source) | None)."""
    if platform == "win32":
        inv = _windows_inventory(runner)
        return [a.name for a in inv.adapters], power_findings(inv.adapters, intent), inv.gateway
    if platform.startswith("linux"):
        wired, findings = _linux_findings(intent, runner, sys_net, unjudged)
        rc, out, _ = _run(runner, ["ip", "-4", "route", "show", "default"], timeout=10)
        routes = sorted((r for r in parse_linux_default_routes(out) if r[1] in wired),
                        key=lambda r: r[2]) if rc == 0 else []
        gw = (routes[0][0], routes[0][1], "") if routes else None
        return wired, findings, gw
    raise CouldNotRunError(f"platform {platform!r} is not supported (Windows and Linux are)")


def check(intent: Intent, platform: str | None = None, runner: Runner | None = None,
          probe: bool = True, count: int = DEFAULT_COUNT,
          sys_net: Path = Path("/sys/class/net")) -> Report:
    """Judge this machine against the intent. See the module doc for exit codes."""
    platform = platform or _platform()
    runner = runner or _default_runner
    lines: list = []
    unjudged: list = []
    try:
        wired, findings, gw = _collect(intent, platform, runner, sys_net, unjudged)
    except CouldNotRunError as exc:
        return Report(exit_code=2, lines=[f"DEAD: {exc}"], unjudged=[str(exc)])
    lines.append(f"intent: wired_power_saving={intent.wired_power_saving} "
                 f"latency_max_ms={intent.latency_max_ms:g} ({intent.source})")
    if not wired:
        msg = "no physical wired adapter found: nothing to judge"
        return Report(exit_code=2, lines=lines + [f"UNJUDGED  {msg}"], unjudged=[msg])
    lines.append("wired: " + ", ".join(wired))
    for f in findings:
        mark = "ok   " if f.ok else "DRIFT"
        tail = "" if f.ok else f"  (want {f.want})"
        lines.append(f"  {mark} {f.adapter}: {f.setting} = {f.current}{tail}")
    managed = [n for n in wired if intent.mode_for(n) == "off"]
    if managed and not findings and not unjudged:
        lines.append("  ok    no power-saving switch exposed by the driver")
    lines.extend(f"  UNJUDGED {u}" for u in unjudged)
    drift = sum(1 for f in findings if not f.ok)
    latency = None
    if probe:
        if gw is None:
            unjudged.append("no default route over a wired adapter: latency not probed")
            lines.append(f"  UNJUDGED {unjudged[-1]}")
        else:
            try:
                stats = _ping(platform, gw[0], gw[2], gw[1], count, runner)
            except CouldNotRunError as exc:
                stats = None
                unjudged.append(str(exc))
                lines.append(f"  UNJUDGED {exc}")
            if stats is not None:
                latency = {"gateway": gw[0], "via": gw[1], **asdict(stats),
                           "max_avg_ms": intent.latency_max_ms}
                if stats.received == 0:
                    unjudged.append(f"latency: 0/{stats.sent} replies from the gateway")
                    lines.append(f"  UNJUDGED {unjudged[-1]}")
                else:
                    high = stats.avg_ms is not None and stats.avg_ms > intent.latency_max_ms
                    latency["high"] = high
                    drift += 1 if high else 0
                    lines.append(
                        f"  {'HIGH ' if high else 'ok   '} latency to gateway via {gw[1]}: "
                        f"{stats.received}/{stats.sent} replies, avg {stats.avg_ms:.1f} ms, "
                        f"max {stats.max_ms:.0f} ms (limit avg {intent.latency_max_ms:g} ms)")
    if drift:
        code = 1
        lines.append(f"verdict: DRIFT ({drift}) -- `awsettings network apply` fixes the "
                     f"power-saving switches; high latency with none left is not this")
    elif unjudged:
        code = 2
        lines.append("verdict: COULD NOT JUDGE (see UNJUDGED)")
    else:
        code = 0
        lines.append("verdict: ok")
    return Report(exit_code=code, lines=lines, findings=findings, latency=latency,
                  unjudged=unjudged)


def apply(intent: Intent, platform: str | None = None, runner: Runner | None = None,
          is_admin: Callable | None = None, state_dir: Path | None = None,
          dry_run: bool = False, sys_net: Path = Path("/sys/class/net")) -> tuple:
    """Turn every drifted switch off, elevating once. (exit code, lines). Idempotent."""
    platform = platform or _platform()
    runner = runner or _default_runner
    is_admin = is_admin or _is_admin
    state_dir = state_dir or _state_dir()
    unjudged: list = []
    try:
        wired, findings, _gw = _collect(intent, platform, runner, sys_net, unjudged)
    except CouldNotRunError as exc:
        return (2, [f"DEAD: {exc}"])
    if not wired:
        return (2, ["no physical wired adapter found: nothing to apply"])
    todo = [f for f in findings if not f.ok]
    if not todo:
        tail = f" ({len(unjudged)} unjudged)" if unjudged else ""
        return (2 if unjudged else 0, [f"nothing to do: {len(findings)} switch(es) already "
                                       f"off on {', '.join(wired)}{tail}"] +
                [f"UNJUDGED {u}" for u in unjudged])
    lines = [f"{'would set' if dry_run else 'set'} {f.adapter}: {f.setting} "
             f"{f.current} -> {f.want}" for f in todo]
    if dry_run:
        return (1, lines + ["dry run: nothing changed"])
    lines.append("each touched adapter restarts once: its link drops for a few seconds")
    if platform == "win32":
        changes = [_Change(adapter=f.adapter, display_name=f.setting, value=f.want)
                   for f in todo]
        rc, msg = _windows_apply(changes, runner, is_admin, state_dir)
    else:
        names = sorted({f.adapter for f in todo})
        if any(not _SAFE_IFNAME.match(n) for n in names):
            return (2, lines + ["refusing an interface name that is not a plain token"])
        script = "; ".join(f"ethtool --set-eee {n} eee off" for n in names)
        cmd = ["sh", "-c", script] if is_admin() else ["sudo", "sh", "-c", script]
        rc0, out, err = _run(runner, cmd, timeout=120)
        rc, msg = ((0, f"ethtool set EEE off on {', '.join(names)}") if rc0 == 0 else
                   (2, f"ethtool/sudo failed (rc {rc0}): {(err or out).strip()[:300]}"))
        lines.append("note: ethtool settings do not survive a reboot; persist with your "
                     "network manager (e.g. a udev rule or NetworkManager dispatcher)")
    lines.append(msg)
    if rc == 2:
        return (2, lines)
    after = check(intent, platform=platform, runner=runner, probe=False, sys_net=sys_net)
    left = [f for f in after.findings if not f.ok]
    if after.exit_code == 2 and not after.findings:
        return (2, lines + ["re-check could not judge"] + after.lines)
    if left:
        return (1, lines + [f"still drifted: {f.adapter}: {f.setting} = {f.current}"
                            for f in left])
    return (rc, lines + ["re-check: every power-saving switch is off"])


@dataclass
class _Change:
    adapter: str
    display_name: str
    value: str


# --- cli -------------------------------------------------------------------------------


def add_arguments(p) -> None:
    sub = p.add_subparsers(dest="network_cmd")
    sub.add_parser("show", help="the intent and the file it lives in")
    c = sub.add_parser("check", help="0 ok, 1 drift, 2 could not judge")
    c.add_argument("--json", action="store_true")
    c.add_argument("--count", type=int, default=DEFAULT_COUNT, help="pings to the gateway")
    c.add_argument("--no-probe", action="store_true", help="skip the latency probe")
    a = sub.add_parser("apply", help="turn wired power saving off (one UAC/sudo prompt)")
    a.add_argument("--dry-run", action="store_true")


def cmd_network(args) -> int:
    action = getattr(args, "network_cmd", None) or "check"
    intent = load_intent()
    if action == "show":
        print(json.dumps({"path": str(network_intent_path()), **asdict(intent)}, indent=2))
        return 0
    if action == "apply":
        rc, lines = apply(intent, runner=_default_runner, platform=_platform(),
                          dry_run=bool(getattr(args, "dry_run", False)))
        for line in lines:
            print(line)
        return rc
    rep = check(intent, runner=_default_runner, platform=_platform(),
                probe=not getattr(args, "no_probe", False),
                count=max(1, int(getattr(args, "count", DEFAULT_COUNT) or DEFAULT_COUNT)))
    if getattr(args, "json", False):
        print(json.dumps(rep.as_json(), indent=2))
    else:
        for line in rep.lines:
            print(line)
    return rep.exit_code


def self_test() -> list:
    """Problems found (empty = ok). Offline: proves the matchers can still say no."""
    problems = []
    for name in ("Energy-Efficient Ethernet", "Energy Efficient Ethernet", "Green Ethernet",
                 "Advanced EEE", "Gigabit Lite", "Power Saving Mode"):
        if not POWER_SAVING_NAMES.match(name):
            problems.append(f"power-saving matcher misses {name!r}")
    for name in ("EEE Max Support Speed", "Wake on Magic Packet", "Flow Control"):
        if POWER_SAVING_NAMES.match(name):
            problems.append(f"power-saving matcher would touch {name!r}")
    if is_wired_physical({"NdisPhysicalMedium": 9, "InterfaceDescription": "x"}):
        problems.append("a Wi-Fi medium was judged wired")
    if is_wired_physical({"NdisPhysicalMedium": 14,
                          "InterfaceDescription": "Hyper-V Virtual Ethernet Adapter"}):
        problems.append("a virtual switch was judged physical")
    if off_value(["100 Mbps Full Duplex", "1.0 Gbps Full Duplex"]) is not None:
        problems.append("a speed list was read as a switch")
    if parse_ping("Minimum = 0ms, Maximum = 6ms, Average = 2ms").received != 0:
        problems.append("the ping summary was counted as replies")
    return problems
