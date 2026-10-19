"""The ``network`` domain: wired NIC power saving off, and a gateway latency probe.

What these tests pin:

* only PHYSICAL WIRED adapters are ever judged or touched -- Wi-Fi, Bluetooth and
  virtual switches are invisible to apply, whatever their properties are called;
* the power-saving properties are matched by NAME across vendors (Realtek, Intel),
  and a property whose values are not an on/off switch (``EEE Max Support Speed``)
  is never touched;
* ``check`` exits 0 ok / 1 drift / 2 could-not-judge -- never 0 when it could not look;
* ``apply`` is idempotent (nothing drifted = no command, no UAC prompt) and elevates
  ONCE for all of its changes;
* the per-adapter overrides are machine facts: they never travel and never arrive.

No test runs PowerShell, ethtool or ping: every command goes through an injected runner.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from awsettings import cli, network
from awsettings.core import merge, redact
from awsettings.domains import all_domains, get_domain, network_intent_path

NET = get_domain("network")


def _prop(name, value, keyword, valid):
    return {"DisplayName": name, "DisplayValue": value, "RegistryKeyword": keyword,
            "ValidDisplayValues": valid}


REALTEK_DRIFTED = [
    _prop("Energy-Efficient Ethernet", "Enabled", "*EEE", ["Disabled", "Enabled"]),
    _prop("Advanced EEE", "Disabled", "AdvancedEEE", ["Disabled", "Enabled"]),
    _prop("EEE Max Support Speed", "1.0 Gbps Full Duplex", "EEEMaxSupportSpeed",
          ["100 Mbps Full Duplex", "1.0 Gbps Full Duplex"]),
    _prop("Green Ethernet", "Enabled", "EnableGreenEthernet", ["Disabled", "Enabled"]),
    _prop("Gigabit Lite", "Disabled", "GigaLite", ["Disabled", "Enabled"]),
    _prop("Power Saving Mode", "Enabled", "PowerSavingMode", ["Disabled", "Enabled"]),
    _prop("Flow Control", "Rx & Tx Enabled", "*FlowControl", ["Disabled", "Rx & Tx Enabled"]),
    _prop("Wake on Magic Packet", "Enabled", "*WakeOnMagicPacket", ["Disabled", "Enabled"]),
]

INTEL_OK = [
    _prop("Energy Efficient Ethernet", "Off", "*EEE", ["Off", "On"]),
    _prop("Interrupt Moderation", "Enabled", "*InterruptModeration", ["Disabled", "Enabled"]),
]

WIFI_PROPS = [
    # A Wi-Fi driver with a "Power Saving Mode": must be invisible to this domain.
    _prop("Power Saving Mode", "Enabled", "PowerSavingMode", ["Disabled", "Enabled"]),
]


def _adapter(name, desc, medium, props, if_index, status="Up", virtual=False):
    return {"Name": name, "InterfaceDescription": desc, "NdisPhysicalMedium": medium,
            "Virtual": virtual, "Status": status, "LinkSpeed": "2.5 Gbps",
            "ifIndex": if_index, "Properties": props}


def _inventory(*adapters, routes=None, addrs=None):
    return json.dumps({
        "adapters": list(adapters),
        "routes": routes if routes is not None else [
            {"ifIndex": 7, "NextHop": "10.0.0.1", "RouteMetric": 0, "InterfaceMetric": 25},
            {"ifIndex": 9, "NextHop": "10.0.0.1", "RouteMetric": 0, "InterfaceMetric": 40},
        ],
        "addresses": addrs if addrs is not None else [
            {"ifIndex": 7, "IPAddress": "10.0.0.20"},
            {"ifIndex": 9, "IPAddress": "10.0.0.21"},
        ],
    })


WIN_PING_GOOD = """
Pinging 10.0.0.1 with 32 bytes of data:
Reply from 10.0.0.1: bytes=32 time=3ms TTL=64
Reply from 10.0.0.1: bytes=32 time<1ms TTL=64
Reply from 10.0.0.1: bytes=32 time=2ms TTL=64
Reply from 10.0.0.1: bytes=32 time=6ms TTL=64

Ping statistics for 10.0.0.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 6ms, Average = 2ms
"""

WIN_PING_JITTER = """
Reply from 10.0.0.1: bytes=32 time=10ms TTL=64
Reply from 10.0.0.1: bytes=32 time=159ms TTL=64
Reply from 10.0.0.1: bytes=32 time=31ms TTL=64
Request timed out.
"""

LINUX_PING = """PING 10.0.0.1 (10.0.0.1) from 10.0.0.30 eth0: 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.412 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=1.20 ms
64 bytes from 10.0.0.1: icmp_seq=3 ttl=64 time=0.388 ms

--- 10.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 405ms
rtt min/avg/max/mdev = 0.388/0.666/1.200/0.377 ms
"""


class FakeRunner:
    """Answers commands by the first matching substring; records every call."""

    def __init__(self, answers):
        self.answers = answers
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout=60.0):
        self.calls.append(list(cmd))
        joined = " ".join(cmd)
        for needle, answer in self.answers:
            if needle in joined:
                return answer(cmd) if callable(answer) else answer
        return (127, "", f"no fake for {joined}")


@pytest.fixture()
def intent_file(tmp_path, monkeypatch):
    target = tmp_path / "network.json"
    monkeypatch.setenv("AWSETTINGS_NETWORK_FILE", str(target))
    return target


# --- the domain: what travels ----------------------------------------------


def test_registered_with_its_own_namespace():
    assert "network" in all_domains()
    assert NET.namespace not in {d.namespace for n, d in all_domains().items() if n != "network"}


def test_override_wins_and_default_is_under_dot_aither(intent_file, monkeypatch):
    assert network_intent_path() == intent_file.resolve()
    monkeypatch.delenv("AWSETTINGS_NETWORK_FILE")
    assert network_intent_path().as_posix().endswith("/.aither/network.json")


def test_the_intent_travels_the_adapter_overrides_stay_home():
    here = {"version": 1, "wired_power_saving": "off", "latency_max_ms": 5,
            "adapters": {"Ethernet 3": "unmanaged"}}
    out = redact(here, domain=NET)
    assert out["wired_power_saving"] == "off" and out["latency_max_ms"] == 5
    assert "adapters" not in out


def test_an_arriving_adapter_override_is_refused():
    here = {"version": 1, "adapters": {"Ethernet": "off"}}
    arriving = {"version": 1, "wired_power_saving": "unmanaged",
                "adapters": {"Ethernet": "unmanaged"}}
    both = merge(here, arriving, domain=NET)
    assert both["adapters"] == {"Ethernet": "off"}
    assert both["wired_power_saving"] == "unmanaged"


# --- intent ------------------------------------------------------------------


def test_missing_file_means_power_saving_off(intent_file):
    intent = network.load_intent(intent_file)
    assert intent.wired_power_saving == "off"
    assert intent.latency_max_ms == network.DEFAULT_LATENCY_MAX_MS == 5.0
    assert intent.source == "default"


def test_a_bad_value_cannot_be_judged(intent_file):
    intent_file.write_text(json.dumps({"wired_power_saving": "maybe"}), encoding="utf-8")
    with pytest.raises(network.CouldNotRunError):
        network.load_intent(intent_file)


def test_adapter_override_unmanaged_is_honoured(intent_file):
    intent_file.write_text(json.dumps({"adapters": {"Ethernet": "unmanaged"}}),
                           encoding="utf-8")
    intent = network.load_intent(intent_file)
    assert intent.mode_for("Ethernet") == "unmanaged"
    assert intent.mode_for("Ethernet 2") == "off"


# --- windows: which adapters, which properties --------------------------------


def test_only_physical_wired_adapters_are_selected():
    inv = network.parse_windows_inventory(_inventory(
        _adapter("Ethernet", "Realtek PCIe 2.5GbE Family Controller", 14, REALTEK_DRIFTED, 7),
        _adapter("Wi-Fi", "Realtek WiFi 7 PCI-E NIC", 9, WIFI_PROPS, 9),
        _adapter("vEthernet (Ext)", "Hyper-V Virtual Ethernet Adapter", 14, REALTEK_DRIFTED, 11,
                 virtual=True),
        _adapter("Bluetooth", "Bluetooth Device (Personal Area Network)", 10, [], 12),
        _adapter("VPN", "WireGuard Tunnel", 14, REALTEK_DRIFTED, 13),
    ))
    assert [a.name for a in inv.adapters] == ["Ethernet"]


def test_realtek_drift_names_exactly_the_power_switches():
    inv = network.parse_windows_inventory(_inventory(
        _adapter("Ethernet", "Realtek PCIe 2.5GbE Family Controller", 14, REALTEK_DRIFTED, 7)))
    findings = network.power_findings(inv.adapters, network.Intent())
    by_name = {f.setting: f for f in findings}
    assert set(by_name) == {"Energy-Efficient Ethernet", "Advanced EEE", "Green Ethernet",
                            "Gigabit Lite", "Power Saving Mode"}
    assert "EEE Max Support Speed" not in by_name           # not an on/off switch
    assert "Wake on Magic Packet" not in by_name
    drifted = sorted(f.setting for f in findings if not f.ok)
    assert drifted == ["Energy-Efficient Ethernet", "Green Ethernet", "Power Saving Mode"]
    assert all(f.want == "Disabled" for f in findings)


def test_intel_off_value_is_understood():
    inv = network.parse_windows_inventory(_inventory(
        _adapter("Ethernet", "Intel(R) Ethernet Connection (17) I219-LM", 14, INTEL_OK, 7)))
    findings = network.power_findings(inv.adapters, network.Intent())
    assert [(f.setting, f.current, f.want, f.ok) for f in findings] == [
        ("Energy Efficient Ethernet", "Off", "Off", True)]


def test_single_adapter_json_object_is_accepted():
    # PowerShell 5.1 unrolls one-element arrays into a bare object.
    raw = json.loads(_inventory(
        _adapter("Ethernet", "Intel(R) Ethernet Controller I226-V", 14, INTEL_OK[0], 7)))
    raw["adapters"] = raw["adapters"][0]
    inv = network.parse_windows_inventory(json.dumps(raw))
    assert inv.adapters[0].props[0].display_name == "Energy Efficient Ethernet"


def test_unmanaged_adapter_is_not_judged():
    inv = network.parse_windows_inventory(_inventory(
        _adapter("Ethernet", "Realtek PCIe GbE Family Controller", 14, REALTEK_DRIFTED, 7)))
    intent = network.Intent(adapters={"Ethernet": "unmanaged"})
    assert network.power_findings(inv.adapters, intent) == []


def test_gateway_prefers_the_wired_route():
    inv = network.parse_windows_inventory(_inventory(
        _adapter("Ethernet", "Realtek PCIe 2.5GbE Family Controller", 14, INTEL_OK, 7),
        _adapter("Wi-Fi", "Realtek WiFi", 9, [], 9)))
    assert inv.gateway == ("10.0.0.1", "Ethernet", "10.0.0.20")


# --- ping ---------------------------------------------------------------------


def test_windows_ping_parses_reply_lines_only():
    stats = network.parse_ping(WIN_PING_GOOD)
    assert stats.received == 4
    assert stats.max_ms == 6.0
    assert stats.avg_ms == pytest.approx((3 + 0.5 + 2 + 6) / 4)


def test_jitter_and_loss_are_reported():
    stats = network.parse_ping(WIN_PING_JITTER, sent=4)
    assert stats.received == 3 and stats.sent == 4
    assert stats.max_ms == 159.0
    assert stats.avg_ms > 5


def test_linux_ping_parses():
    stats = network.parse_ping(LINUX_PING)
    assert stats.received == 3
    assert stats.avg_ms == pytest.approx((0.412 + 1.20 + 0.388) / 3)


# --- check: exit codes ----------------------------------------------------------


def _win_runner(props, ping=WIN_PING_GOOD, admin=True):
    inv = _inventory(_adapter("Ethernet", "Realtek PCIe 2.5GbE Family Controller", 14, props, 7))
    return FakeRunner([("Get-NetAdapter", (0, inv, "")), ("ping", (0, ping, ""))])


def test_check_ok_is_zero(intent_file, capsys):
    ok_props = [dict(p, DisplayValue="Disabled") if p["RegistryKeyword"] in (
        "*EEE", "EnableGreenEthernet", "PowerSavingMode") else p for p in REALTEK_DRIFTED]
    rep = network.check(network.load_intent(intent_file), platform="win32",
                        runner=_win_runner(ok_props), count=4)
    assert rep.exit_code == 0, rep.lines


def test_check_drift_is_one():
    rep = network.check(network.Intent(), platform="win32", runner=_win_runner(REALTEK_DRIFTED),
                        count=4)
    assert rep.exit_code == 1


def test_check_high_latency_on_wired_is_drift():
    rep = network.check(network.Intent(), platform="win32",
                        runner=_win_runner(INTEL_OK, ping=WIN_PING_JITTER), count=4)
    assert rep.exit_code == 1
    assert any("latency" in line and "HIGH" in line for line in rep.lines)


def test_check_without_powershell_cannot_judge():
    runner = FakeRunner([])
    rep = network.check(network.Intent(), platform="win32", runner=runner, count=4)
    assert rep.exit_code == 2


def test_check_with_no_wired_adapter_cannot_judge():
    inv = _inventory(_adapter("Wi-Fi", "Realtek WiFi", 9, WIFI_PROPS, 9))
    runner = FakeRunner([("Get-NetAdapter", (0, inv, "")), ("ping", (0, WIN_PING_GOOD, ""))])
    rep = network.check(network.Intent(), platform="win32", runner=runner, count=4)
    assert rep.exit_code == 2


def test_all_pings_lost_cannot_judge_latency():
    rep = network.check(network.Intent(), platform="win32",
                        runner=_win_runner(INTEL_OK, ping="Request timed out.\n" * 4), count=4)
    assert rep.exit_code == 2


def test_no_probe_skips_ping():
    runner = _win_runner(INTEL_OK)
    rep = network.check(network.Intent(), platform="win32", runner=runner, probe=False)
    assert rep.exit_code == 0
    assert not any(c[0] == "ping" for c in runner.calls)


# --- apply (windows) ----------------------------------------------------------------


def test_apply_with_nothing_drifted_runs_nothing(tmp_path):
    runner = _win_runner(INTEL_OK)
    rc, lines = network.apply(network.Intent(), platform="win32", runner=runner,
                              is_admin=lambda: False, state_dir=tmp_path)
    assert rc == 0
    assert not any("Set-NetAdapterAdvancedProperty" in " ".join(c) or "RunAs" in " ".join(c)
                   for c in runner.calls)


def test_apply_elevates_once_and_reads_the_result_file(tmp_path):
    state = {"props": [dict(p) for p in REALTEK_DRIFTED]}

    def inventory(_cmd):
        return (0, _inventory(_adapter("Ethernet", "Realtek PCIe 2.5GbE Family Controller", 14,
                                       state["props"], 7)), "")

    def elevate(cmd):
        joined = " ".join(cmd)
        assert "RunAs" in joined
        plan = json.loads((tmp_path / "apply-plan.json").read_text(encoding="utf-8"))
        assert {(c["adapter"], c["display_name"], c["value"]) for c in plan["changes"]} == {
            ("Ethernet", "Energy-Efficient Ethernet", "Disabled"),
            ("Ethernet", "Green Ethernet", "Disabled"),
            ("Ethernet", "Power Saving Mode", "Disabled")}
        for p in state["props"]:
            if p["DisplayName"] in {c["display_name"] for c in plan["changes"]}:
                p["DisplayValue"] = "Disabled"
        (tmp_path / "last-apply.json").write_text(json.dumps(
            {"exit_code": 0, "applied": len(plan["changes"]), "errors": []}), encoding="utf-8")
        return (0, "", "")

    runner = FakeRunner([("RunAs", elevate), ("Get-NetAdapter", inventory)])
    rc, lines = network.apply(network.Intent(), platform="win32", runner=runner,
                              is_admin=lambda: False, state_dir=tmp_path)
    assert rc == 0, lines
    assert sum("RunAs" in " ".join(c) for c in runner.calls) == 1
    # Idempotent: a second apply finds nothing and prompts nothing.
    rc2, _ = network.apply(network.Intent(), platform="win32", runner=runner,
                           is_admin=lambda: False, state_dir=tmp_path)
    assert rc2 == 0
    assert sum("RunAs" in " ".join(c) for c in runner.calls) == 1


def test_apply_declined_uac_cannot_judge(tmp_path):
    runner = FakeRunner([
        ("RunAs", (1, "", "The operation was canceled by the user.")),
        ("Get-NetAdapter", _win_runner(REALTEK_DRIFTED).answers[0][1]),
    ])
    rc, lines = network.apply(network.Intent(), platform="win32", runner=runner,
                              is_admin=lambda: False, state_dir=tmp_path)
    assert rc == 2


def test_apply_as_admin_does_not_prompt(tmp_path):
    state = {"props": [dict(p) for p in REALTEK_DRIFTED]}

    def inventory(_cmd):
        return (0, _inventory(_adapter("Ethernet", "Realtek PCIe 2.5GbE Family Controller", 14,
                                       state["props"], 7)), "")

    def direct(cmd):
        assert "RunAs" not in " ".join(cmd)
        for p in state["props"]:
            if p["RegistryKeyword"] in ("*EEE", "EnableGreenEthernet", "PowerSavingMode"):
                p["DisplayValue"] = "Disabled"
        (tmp_path / "last-apply.json").write_text(json.dumps(
            {"exit_code": 0, "applied": 3, "errors": []}), encoding="utf-8")
        return (0, "", "")

    runner = FakeRunner([("apply-network.ps1", direct), ("Get-NetAdapter", inventory)])
    rc, lines = network.apply(network.Intent(), platform="win32", runner=runner,
                              is_admin=lambda: True, state_dir=tmp_path)
    assert rc == 0, lines


def test_dry_run_changes_nothing(tmp_path):
    runner = _win_runner(REALTEK_DRIFTED)
    rc, lines = network.apply(network.Intent(), platform="win32", runner=runner,
                              is_admin=lambda: False, state_dir=tmp_path, dry_run=True)
    assert rc == 1                       # drift exists and was left alone
    assert len(runner.calls) == 1        # the inventory read only
    assert any("Green Ethernet" in line for line in lines)


# --- linux --------------------------------------------------------------------------


def _sys_net(tmp_path: Path) -> Path:
    root = tmp_path / "sys-class-net"
    for name, wired in (("eno1", True), ("wlp2s0", False), ("docker0", None), ("lo", None)):
        d = root / name
        d.mkdir(parents=True)
        (d / "type").write_text("1\n" if name != "lo" else "772\n")
        if wired is not None:
            (d / "device").mkdir()
        if wired is False:
            (d / "wireless").mkdir()
    return root


ETHTOOL_ON = """EEE settings for eno1:
	EEE status: enabled - active
	Tx LPI: 17 (us)
	Supported EEE link modes:  100baseT/Full
"""
ETHTOOL_OFF = """EEE settings for eno1:
	EEE status: disabled
	Tx LPI: disabled
"""


def test_linux_wired_detection(tmp_path):
    assert network.linux_wired_interfaces(_sys_net(tmp_path)) == ["eno1"]


def test_ethtool_parse():
    assert network.parse_ethtool_eee(ETHTOOL_ON, 0) == "enabled"
    assert network.parse_ethtool_eee(ETHTOOL_OFF, 0) == "disabled"
    assert network.parse_ethtool_eee("EEE status: not supported\n", 0) == "unsupported"
    assert network.parse_ethtool_eee("", 95) == "unsupported"   # Operation not supported
    assert network.parse_ethtool_eee("garbage", 0) is None


def test_linux_default_route_parse():
    text = ("default via 10.0.0.1 dev wlp2s0 proto dhcp metric 600\n"
            "default via 10.0.0.1 dev eno1 proto dhcp metric 100\n")
    assert network.parse_linux_default_routes(text) == [
        ("10.0.0.1", "wlp2s0", 600), ("10.0.0.1", "eno1", 100)]


def test_linux_check_and_apply_with_one_sudo(tmp_path):
    sysnet = _sys_net(tmp_path)
    state = {"eee": ETHTOOL_ON}

    def set_eee(cmd):
        assert cmd[0] == "sudo"
        assert "--set-eee" in " ".join(cmd) and "wlp2s0" not in " ".join(cmd)
        state["eee"] = ETHTOOL_OFF
        return (0, "", "")

    runner = FakeRunner([
        ("--set-eee", set_eee),
        ("--show-eee eno1", lambda _c: (0, state["eee"], "")),
        ("route show default", (0, "default via 10.0.0.1 dev eno1 metric 100\n", "")),
        ("ping", (0, LINUX_PING, "")),
    ])
    rep = network.check(network.Intent(), platform="linux", runner=runner, sys_net=sysnet,
                        count=3)
    assert rep.exit_code == 1
    rc, lines = network.apply(network.Intent(), platform="linux", runner=runner,
                              is_admin=lambda: False, state_dir=tmp_path, sys_net=sysnet)
    assert rc == 0, lines
    assert sum(c[0] == "sudo" for c in runner.calls) == 1
    rep2 = network.check(network.Intent(), platform="linux", runner=runner, sys_net=sysnet,
                         count=3)
    assert rep2.exit_code == 0, rep2.lines


# --- cli ---------------------------------------------------------------------------


def test_cli_network_check_wires_through(monkeypatch, intent_file, capsys):
    monkeypatch.setattr(network, "_default_runner", _win_runner(INTEL_OK))
    monkeypatch.setattr(network, "_platform", lambda: "win32")
    rc = cli.main(["network", "check", "--count", "4"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "Energy Efficient Ethernet" in out


def test_cli_network_check_json(monkeypatch, intent_file, capsys):
    monkeypatch.setattr(network, "_default_runner", _win_runner(REALTEK_DRIFTED))
    monkeypatch.setattr(network, "_platform", lambda: "win32")
    rc = cli.main(["network", "check", "--json", "--no-probe"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1 and data["exit_code"] == 1
    assert any(not f["ok"] for f in data["findings"])


def test_self_test_passes():
    assert network.self_test() == []


def test_gateway_over_a_hyperv_external_switch_counts_as_wired():
    # The physical NIC is bound to an external vSwitch: the route is on the host vNIC.
    raw = json.loads(_inventory(
        _adapter("Ethernet", "Intel(R) Ethernet Connection (14) I219-LM", 14, INTEL_OK, 12),
        routes=[{"ifIndex": 8, "NextHop": "10.0.0.1", "RouteMetric": 0, "InterfaceMetric": 15}],
        addrs=[{"ifIndex": 8, "IPAddress": "10.0.0.40"}]))
    raw["switches"] = [{"Name": "External", "NetAdapterInterfaceDescription":
                        "Intel(R) Ethernet Connection (14) I219-LM"}]
    raw["vnics"] = [{"Name": "vEthernet (External)", "ifIndex": 8},
                    {"Name": "vEthernet (Internal)", "ifIndex": 13}]
    inv = network.parse_windows_inventory(json.dumps(raw))
    assert [a.name for a in inv.adapters] == ["Ethernet"]
    assert inv.gateway == ("10.0.0.1", "vEthernet (External) -> Ethernet", "10.0.0.40")


def test_an_internal_switch_route_is_not_wired():
    raw = json.loads(_inventory(
        _adapter("Ethernet", "Intel(R) Ethernet Connection I219-V", 14, INTEL_OK, 12),
        routes=[{"ifIndex": 13, "NextHop": "172.16.0.1", "RouteMetric": 0,
                 "InterfaceMetric": 5}], addrs=[]))
    raw["switches"] = []
    raw["vnics"] = [{"Name": "vEthernet (Internal)", "ifIndex": 13}]
    assert network.parse_windows_inventory(json.dumps(raw)).gateway is None


# --- dual-homed: wired AND Wi-Fi up on one subnet ------------------------------------


def _dual_inventory(wifi_status="Up", wifi_ip="10.0.0.21", wired_status="Up"):
    raw = json.loads(_inventory(
        _adapter("Ethernet", "Realtek PCIe 2.5GbE Family Controller", 14, INTEL_OK, 7,
                 status=wired_status),
        _adapter("Wi-Fi", "Realtek WiFi 7 PCI-E NIC", 9, WIFI_PROPS, 9, status=wifi_status),
        addrs=[{"ifIndex": 7, "IPAddress": "10.0.0.20", "PrefixLength": 24},
               {"ifIndex": 9, "IPAddress": wifi_ip, "PrefixLength": 24}]))
    return json.dumps(raw)


def test_dual_homed_same_subnet_is_drift():
    inv = network.parse_windows_inventory(_dual_inventory())
    assert [a.name for a in inv.wifi] == ["Wi-Fi"]
    found = network.dualhome_findings(inv.adapters, inv.wifi, network.Intent())
    assert [(f.kind, f.adapter, f.ok) for f in found] == [("wifi", "Wi-Fi", False)]


def test_wifi_on_another_subnet_is_not_dual_homed():
    inv = network.parse_windows_inventory(_dual_inventory(wifi_ip="172.16.5.9"))
    assert network.dualhome_findings(inv.adapters, inv.wifi, network.Intent()) == []


def test_wifi_kept_when_intent_says_keep():
    inv = network.parse_windows_inventory(_dual_inventory())
    assert network.dualhome_findings(inv.adapters, inv.wifi,
                                     network.Intent(wifi_when_wired="keep")) == []


def test_wired_down_means_wifi_is_left_alone():
    inv = network.parse_windows_inventory(_dual_inventory(wired_status="Disconnected"))
    assert network.dualhome_findings(inv.adapters, inv.wifi, network.Intent()) == []


def test_wifi_when_wired_travels(intent_file):
    out = redact({"version": 1, "wifi_when_wired": "keep"}, domain=NET)
    assert out["wifi_when_wired"] == "keep"
    intent_file.write_text(json.dumps({"wifi_when_wired": "sometimes"}), encoding="utf-8")
    with pytest.raises(network.CouldNotRunError):
        network.load_intent(intent_file)


def test_apply_disables_wifi_in_the_same_single_elevation(tmp_path):
    state = {"wifi": "Up"}

    def inventory(_cmd):
        return (0, _dual_inventory(wifi_status=state["wifi"]), "")

    def elevate(cmd):
        plan = json.loads((tmp_path / "apply-plan.json").read_text(encoding="utf-8"))
        assert plan["changes"] == []
        assert plan["disable_adapters"] == ["Wi-Fi"]
        state["wifi"] = "Disabled"
        (tmp_path / "last-apply.json").write_text(json.dumps(
            {"exit_code": 0, "applied": 1, "errors": []}), encoding="utf-8")
        return (0, "", "")

    runner = FakeRunner([("RunAs", elevate), ("Get-NetAdapter", inventory)])
    rc, lines = network.apply(network.Intent(), platform="win32", runner=runner,
                              is_admin=lambda: False, state_dir=tmp_path)
    assert rc == 0, lines
    assert sum("RunAs" in " ".join(c) for c in runner.calls) == 1


def test_linux_dual_homed(tmp_path):
    sysnet = _sys_net(tmp_path)
    for name in ("eno1", "wlp2s0"):
        (sysnet / name / "operstate").write_text("up\n")
    addr = ("2: eno1    inet 10.0.0.30/24 brd 10.0.0.255 scope global eno1\n"
            "3: wlp2s0    inet 10.0.0.31/24 brd 10.0.0.255 scope global dynamic wlp2s0\n")
    runner = FakeRunner([("--show-eee eno1", (0, ETHTOOL_OFF, "")),
                         ("addr show", (0, addr, "")),
                         ("route show default", (0, "default via 10.0.0.1 dev eno1\n", ""))])
    rep = network.check(network.Intent(), platform="linux", runner=runner, sys_net=sysnet,
                        probe=False, mesh=False)
    assert rep.exit_code == 1
    assert any(f.kind == "wifi" and f.adapter == "wlp2s0" for f in rep.findings)


# --- mesh overhead: overlay vs raw LAN, and the local client version -------------------


TS_STATUS = json.dumps({
    "Version": "1.98.8-tabc-gdef",
    "Peer": {
        "k1": {"HostName": "node-a", "Online": True, "CurAddr": "10.0.0.112:41641",
               "TailscaleIPs": ["100.64.0.38", "fd7a::26"]},
        "k2": {"HostName": "node-b", "Online": True, "CurAddr": "",
               "TailscaleIPs": ["100.64.0.41"]},                       # relayed: skipped
        "k3": {"HostName": "node-c", "Online": False, "CurAddr": "10.0.0.5:41641",
               "TailscaleIPs": ["100.64.0.5"]},                        # offline: skipped
        "k4": {"HostName": "node-d", "Online": True, "CurAddr": "203.0.113.7:41641",
               "TailscaleIPs": ["100.64.0.7"]},                        # not LAN: skipped
    },
})
TS_NETMAP = json.dumps({"SelfNode": {"Hostinfo": {"IPNVersion": "1.98.8-tabc"}},
                        "Peers": [{"Name": "node-a.example.", "Online": True,
                                   "Hostinfo": {"IPNVersion": "1.104.1-t7f4"}}]})


def _ping_out(ms):
    return "".join(f"Reply from x: bytes=32 time={m}ms TTL=64\n" for m in ms)


def test_version_compare():
    assert network.parse_version("1.98.8-tabc-gdef") == (1, 98, 8)
    assert network.parse_version("1.104.1") > network.parse_version("1.98.8")
    assert network.parse_version("garbage") is None


def test_direct_lan_peers_only():
    peers = network.direct_lan_peers(json.loads(TS_STATUS))
    assert peers == [("node-a", "100.64.0.38", "10.0.0.112")]


def test_mesh_overhead_and_old_client_are_drift():
    runner = FakeRunner([
        ("status --json", (0, TS_STATUS, "")),
        ("debug netmap", (0, TS_NETMAP, "")),
        ("100.64.0.38", (0, _ping_out([180, 190, 195]), "")),
        ("10.0.0.112", (0, _ping_out([1, 2, 1]), "")),
    ])
    rep = network.mesh_report(network.Intent(), platform="win32", runner=runner, count=3)
    assert rep["drift"] == 2, rep["lines"]
    assert any("OVERLAY" in line for line in rep["lines"])
    assert any("older" in line for line in rep["lines"])


def test_mesh_ok():
    status = json.loads(TS_STATUS)
    status["Version"] = "1.104.1-t7f4"
    runner = FakeRunner([
        ("status --json", (0, json.dumps(status), "")),
        ("debug netmap", (0, TS_NETMAP, "")),
        ("100.64.0.38", (0, _ping_out([2, 3, 2]), "")),
        ("10.0.0.112", (0, _ping_out([1, 2, 1]), "")),
    ])
    rep = network.mesh_report(network.Intent(), platform="win32", runner=runner, count=3)
    assert rep["drift"] == 0 and not rep["unjudged"], rep["lines"]


def test_no_tailscale_is_not_applicable_not_unjudged():
    rep = network.mesh_report(network.Intent(), platform="win32", runner=FakeRunner([]),
                              count=3)
    assert rep["drift"] == 0 and rep["unjudged"] == []
    assert any("not installed" in line for line in rep["lines"])


def test_peer_versions_unreadable_does_not_fail_the_overhead_probe():
    runner = FakeRunner([
        ("status --json", (0, TS_STATUS.replace("1.98.8", "1.104.1"), "")),
        ("debug netmap", (1, "", "access denied")),
        ("100.64.0.38", (0, _ping_out([2, 2, 2]), "")),
        ("10.0.0.112", (0, _ping_out([1, 1, 1]), "")),
    ])
    rep = network.mesh_report(network.Intent(), platform="win32", runner=runner, count=3)
    assert rep["drift"] == 0
