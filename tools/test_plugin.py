#!/usr/bin/env python3
"""
tools/test_plugin.py — the plugin's own unit checks, run by CI after
tools/verify.py. Loads plugin.py with importlib against a stub `jen`
package and fake Flask/flask_login modules so nothing here needs Jen, a
database, or a network. Fixture walk texts below are SYNTHESISED from
the verified MIB syntax (BRIDGE-MIB, Q-BRIDGE-MIB, IF-MIB — see
plugin.py's own module docstring for the exact OIDs and sources), not
pasted from a real switch — no real Cisco/HP walk was available when
this was written; the OID-index math is what's actually under test and
is unaffected by which vendor produced it, since the walk output
FORMAT itself is net-snmp's own client-side formatting, not the
switch's.

Run: `python3 tools/test_plugin.py` (exit 1 on the first failing check).
"""

import importlib.util
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _stub_modules():
    """Enough of flask / flask_login for plugin.py to import."""
    flask = types.ModuleType("flask")

    class Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            def deco(fn):
                return fn

            return deco

        def add_url_rule(self, *a, **k):
            pass

    flask.Blueprint = Blueprint
    for name in ("flash", "jsonify", "make_response", "redirect", "render_template", "url_for"):
        setattr(flask, name, lambda *a, **k: None)
    flask.request = None
    sys.modules["flask"] = flask
    fl = types.ModuleType("flask_login")
    fl.current_user = types.SimpleNamespace(username="tester", all_subnets=True, role="admin")
    fl.login_required = lambda fn: fn
    sys.modules["flask_login"] = fl


class _FakeApp:
    def register_blueprint(self, bp):
        pass


def _stub_jen_plugin_api():
    """A stub `jen.plugin_api` sufficient for register(app) to run end to end, enforcing the SAME two
    rules Jen's real one does: an alert type id must start with '<plugin_id>_', and a periodic job may
    not run more often than PERIODIC_MIN_MINUTES (5). A plugin that breaks either raises at register()
    in Jen, is swallowed by its per-plugin error handling, and never loads - the way watchdog 1.0.0 and
    dns-sync 1.0.0 shipped dead (Q89). Returns the registered calls."""
    calls = {"alert_types": [], "periodic": [], "row_actions": [], "search": [], "investigation": []}

    # Jen's own tests (tests/test_q57_quickwins.py, tests/test_icons.py) hold every alert type to these two
    # lists: a default template must open with one of the four standard glyphs, and the icon must be one the
    # dashboard's alert whitelist knows. 1.0.1 used a glyph and an icon outside them and failed Jen's CI.
    glyphs = ("\U0001f6a8", "\u26a0\ufe0f", "\u2705", "\u2139\ufe0f")
    icons = (
        "clock", "trash", "badge-question-mark", "pin", "info", "circle-check", "chart-bar", "siren", "lock",
        "clipboard-list", "triangle-alert", "circle-x", "plus", "zap", "bell", "trending-up",
    )  # fmt: skip

    def register_alert_type(plugin_id, type_id, **kwargs):
        prefix = f"{plugin_id}_"
        if not type_id.startswith(prefix):
            raise ValueError(f"type_id {type_id!r} must start with {prefix!r}")
        lead = kwargs.get("default_template", "").split(" ", 1)[0]
        if lead not in glyphs:
            raise ValueError(f"default_template must open with a standard glyph, got {lead!r}")
        if kwargs.get("icon") not in icons:
            raise ValueError(f"icon {kwargs.get('icon')!r} is not in the dashboard alert-icon whitelist")
        calls["alert_types"].append(type_id)

    def register_periodic(plugin_id, name, fn, every_minutes):
        if every_minutes < 5:
            raise ValueError("every_minutes must be at least 5")
        calls["periodic"].append((plugin_id, name, every_minutes))

    jen_pkg = types.ModuleType("jen")
    plugin_api = types.ModuleType("jen.plugin_api")
    plugin_api.register_alert_type = register_alert_type
    plugin_api.register_periodic = register_periodic
    plugin_api.register_row_action = lambda *a, **k: calls["row_actions"].append(a)
    plugin_api.register_search_provider = lambda *a, **k: calls["search"].append(a)
    plugin_api.register_investigation_provider = lambda *a, **k: calls["investigation"].append((a, k))
    plugin_api.api_key_required = lambda write=False: lambda fn: fn

    def normalize_mac(raw):
        import re as _re

        if not isinstance(raw, str) or not raw.strip():
            return None
        cleaned = _re.sub(r"[^0-9a-fA-F]", "", raw).lower()
        if len(cleaned) != 12:
            return None
        mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
        return mac if _re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac) else None

    plugin_api.normalize_mac = normalize_mac
    plugin_api.like_pattern = lambda text: (
        "%" + str(text).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    )
    jen_pkg.plugin_api = plugin_api
    sys.modules["jen"] = jen_pkg
    sys.modules["jen.plugin_api"] = plugin_api
    return calls


def load_plugin():
    _stub_modules()
    spec = importlib.util.spec_from_file_location("switchport_plugin", os.path.join(ROOT, "plugin.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


failures = []


def check(cond, msg):
    if cond:
        print(f"ok    {msg}")
    else:
        failures.append(msg)
        print(f"FAIL  {msg}")


# ── Synthesised fixture walk texts (see module docstring for why) ──────────────

# "Cisco-style" — BRIDGE-MIB dot1dTpFdbPort, one VLAN's view via community@vlan
# indexing. MAC 00:1a:2b:3c:4d:5e -> decimal subids 0.26.43.60.77.94 (port 12);
# MAC aa:bb:cc:dd:ee:ff -> subids 170.187.204.221.238.255 (port 13).
CISCO_BRIDGE_FDB_WALK = """\
.1.3.6.1.2.1.17.4.3.1.2.0.26.43.60.77.94 = INTEGER: 12
.1.3.6.1.2.1.17.4.3.1.2.170.187.204.221.238.255 = INTEGER: 13
"""

# "HP-style" — Q-BRIDGE-MIB dot1qTpFdbPort, one walk covering every VLAN.
# VLAN 10, MAC 00:1a:2b:3c:4d:5e -> subids 10.0.26.43.60.77.94 (port 5);
# VLAN 20, MAC 11:22:33:44:55:66 -> subids 20.17.34.51.68.85.102 (port 7).
HP_QBRIDGE_FDB_WALK = """\
.1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.26.43.60.77.94 = INTEGER: 5
.1.3.6.1.2.1.17.7.1.2.2.1.2.20.17.34.51.68.85.102 = INTEGER: 7

No Such Object available on this agent at this OID
"""

BASE_PORT_IFINDEX_WALK = """\
.1.3.6.1.2.1.17.1.4.1.2.12 = INTEGER: 10112
.1.3.6.1.2.1.17.1.4.1.2.13 = INTEGER: 10113
.1.3.6.1.2.1.17.1.4.1.2.5 = INTEGER: 10105
.1.3.6.1.2.1.17.1.4.1.2.7 = INTEGER: 10107
"""

IF_NAME_WALK = """\
.1.3.6.1.2.1.31.1.1.1.1.10112 = STRING: "Gi1/0/12"
.1.3.6.1.2.1.31.1.1.1.1.10113 = STRING: "Gi1/0/13"
"""

IF_ALIAS_WALK = """\
.1.3.6.1.2.1.31.1.1.1.18.10112 = STRING: "Desk 12"
.1.3.6.1.2.1.31.1.1.1.18.10113 = STRING: ""
"""


def main():
    p = load_plugin()

    # ── walk-line parsing ─────────────────────────────────────────────────────
    check(
        p.parse_walk_line(".1.3.6.1.2.1.17.4.3.1.2.0.26.43.60.77.94 = INTEGER: 12")
        == ("1.3.6.1.2.1.17.4.3.1.2.0.26.43.60.77.94", "12"),
        "parse_walk_line: a well-formed INTEGER line, leading dot stripped",
    )
    check(
        p.parse_walk_line('.1.3.6.1.2.1.31.1.1.1.1.10112 = STRING: "Gi1/0/12"')
        == ("1.3.6.1.2.1.31.1.1.1.1.10112", "Gi1/0/12"),
        "parse_walk_line: a STRING line has its surrounding quotes stripped",
    )
    check(
        p.parse_walk_line("No Such Object available on this agent at this OID") is None,
        "parse_walk_line: an SNMP error line is refused, not misparsed",
    )
    check(p.parse_walk_line("") is None, "parse_walk_line: a blank line is refused")
    check(p.parse_walk_line("   ") is None, "parse_walk_line: a whitespace-only line is refused")

    # ── OID-index MAC decoding ────────────────────────────────────────────────
    check(
        p.decode_mac_from_subids(["0", "26", "43", "60", "77", "94"]) == "00:1a:2b:3c:4d:5e",
        "decode_mac_from_subids: decimal sub-ids decode to lower-case hex MAC",
    )
    check(
        p.decode_mac_from_subids(["170", "187", "204", "221", "238", "255"]) == "aa:bb:cc:dd:ee:ff",
        "decode_mac_from_subids: values needing two hex digits pad correctly",
    )

    # ── the pure walk parsers (Cisco/BRIDGE-MIB and HP/Q-BRIDGE-MIB fixtures) ──
    bridge_fdb = p.parse_bridge_fdb(CISCO_BRIDGE_FDB_WALK)
    check(
        bridge_fdb == {"00:1a:2b:3c:4d:5e": 12, "aa:bb:cc:dd:ee:ff": 13},
        f"parse_bridge_fdb: Cisco-style BRIDGE-MIB walk decodes both entries (got {bridge_fdb})",
    )
    qbridge_fdb = p.parse_qbridge_fdb(HP_QBRIDGE_FDB_WALK)
    check(
        qbridge_fdb == {"00:1a:2b:3c:4d:5e": (10, 5), "11:22:33:44:55:66": (20, 7)},
        f"parse_qbridge_fdb: HP-style Q-BRIDGE-MIB walk decodes vlan+port, skips the error line (got {qbridge_fdb})",
    )
    port_to_ifindex = p.parse_base_port_ifindex(BASE_PORT_IFINDEX_WALK)
    check(
        port_to_ifindex == {12: 10112, 13: 10113, 5: 10105, 7: 10107},
        f"parse_base_port_ifindex: bridge port -> ifIndex, both cast to int (got {port_to_ifindex})",
    )
    ifnames = p.parse_single_index_walk(IF_NAME_WALK, p.OID_IF_NAME)
    check(
        ifnames == {10112: "Gi1/0/12", 10113: "Gi1/0/13"},
        f"parse_single_index_walk: ifName walk (got {ifnames})",
    )
    ifaliases = p.parse_single_index_walk(IF_ALIAS_WALK, p.OID_IF_ALIAS)
    check(
        ifaliases == {10112: "Desk 12", 10113: ""},
        f"parse_single_index_walk: ifAlias walk, an empty alias is a valid empty string not a drop (got {ifaliases})",
    )

    # ── resolving bridge ports to ifindex ────────────────────────────────────
    resolved = p.resolve_bridge_ports(bridge_fdb, port_to_ifindex, vlan=10)
    check(
        resolved == {"00:1a:2b:3c:4d:5e": (10112, 10), "aa:bb:cc:dd:ee:ff": (10113, 10)},
        f"resolve_bridge_ports: vlan fixed for the whole walk, ifindex resolved (got {resolved})",
    )
    resolved_q = p.resolve_qbridge_ports(qbridge_fdb, port_to_ifindex)
    check(
        resolved_q == {"00:1a:2b:3c:4d:5e": (10105, 10), "11:22:33:44:55:66": (10107, 20)},
        f"resolve_qbridge_ports: each mac keeps its own walked vlan (got {resolved_q})",
    )
    no_ifindex = p.resolve_bridge_ports({"00:11:22:33:44:55": 99}, {}, vlan=1)
    check(no_ifindex == {}, "resolve_bridge_ports: a port with no known ifindex mapping is dropped, not guessed")

    # ── VLAN list parsing ─────────────────────────────────────────────────────
    check(p.parse_vlan_list("10,20,30") == [10, 20, 30], "parse_vlan_list: a clean comma-separated list")
    check(
        p.parse_vlan_list(" 10 , 20 ,, 30 ") == [10, 20, 30], "parse_vlan_list: whitespace and empty entries tolerated"
    )
    check(p.parse_vlan_list("") == [], "parse_vlan_list: an empty string is an empty list, not an error")
    check(p.parse_vlan_list("10,abc,30") == [10, 30], "parse_vlan_list: a non-numeric entry is skipped, not raised on")

    # ── the uplink heuristic ──────────────────────────────────────────────────
    many_macs = {f"mac{i}": (100, 1) for i in range(9)}  # 9 MACs on ifindex 100
    counts = p.mac_counts_by_ifindex(many_macs)
    check(counts == {100: 9}, f"mac_counts_by_ifindex: counts per ifindex (got {counts})")
    check(
        p.auto_uplinks({100: 9, 200: 8, 300: 1}) == {100},
        "auto_uplinks: strictly more than the threshold (8) is an uplink, exactly 8 is not",
    )
    located = p.located_macs(many_macs, auto_uplink_ifindexes={100})
    check(located == {}, "located_macs: every mac behind an auto-detected uplink is excluded")
    pinned_not_uplink = p.located_macs(many_macs, auto_uplink_ifindexes={100}, manual_non_uplinks={100})
    check(
        pinned_not_uplink == many_macs,
        "located_macs: a manual 'not an uplink' pin overrides the auto heuristic even past the threshold",
    )
    small = {"macA": (200, 1)}
    pinned_uplink = p.located_macs(small, auto_uplink_ifindexes=set(), manual_uplinks={200})
    check(pinned_uplink == {}, "located_macs: a manual uplink pin excludes even a port under the count threshold")

    # ── move detection ────────────────────────────────────────────────────────
    moves = p.detect_moves(old_positions={"aa:bb:cc:dd:ee:ff": (1, 12)}, new_positions={"aa:bb:cc:dd:ee:ff": (2, 7)})
    check(
        moves == [("aa:bb:cc:dd:ee:ff", (1, 12), (2, 7))],
        f"detect_moves: a genuine switch+port change is reported (got {moves})",
    )
    no_move = p.detect_moves(old_positions={"aa:bb:cc:dd:ee:ff": (1, 12)}, new_positions={"aa:bb:cc:dd:ee:ff": (1, 12)})
    check(no_move == [], "detect_moves: an unchanged position is not a move")
    new_mac = p.detect_moves(old_positions={}, new_positions={"aa:bb:cc:dd:ee:ff": (1, 12)})
    check(new_mac == [], "detect_moves: a mac never seen before is not a move")

    # ── MAC normalisation ────────────────────────────────────────────────────
    _stub_jen_plugin_api()
    check(p._normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff", "_normalize_mac: uppercase colon form")
    check(p._normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff", "_normalize_mac: bare hex form")
    check(p._normalize_mac("not-a-mac") == "", "_normalize_mac: garbage is refused, not raised")

    # ── write gate — viewers can look at Switch Ports but not change it ─────
    p.current_user.role = "viewer"
    check(p._is_admin() is False, "a viewer is not admin")
    check(p._require_write() is False, "a viewer cannot write")
    for fn, args in (
        (p.add_switch, ()),
        (p.toggle_switch, (1,)),
        (p.delete_switch, (1,)),
        (p.set_uplink, (1, 12)),
    ):
        try:
            fn(*args)
            gated = True
        except Exception:
            gated = False
        check(gated, f"{fn.__name__} refuses a viewer before touching the request")
    p.current_user.role = "admin"
    check(p._is_admin() is True, "admin role restored for the rest of the run")

    # ── 1.0.1: the uplink heuristic's result is visible ───────────────────────
    check(p.port_is_uplink(None, 9) is True, "port_is_uplink: unpinned and over the threshold is an uplink")
    check(p.port_is_uplink(None, 8) is False, "port_is_uplink: exactly the threshold is not")
    check(p.port_is_uplink(1, 0) is True, "port_is_uplink: a manual uplink pin wins under the threshold")
    check(p.port_is_uplink(0, 40) is False, "port_is_uplink: a manual 'not an uplink' pin wins over the threshold")
    check(p.port_is_uplink(None, None) is False, "port_is_uplink: a port with no count yet is not an uplink")

    # ── 1.0.1: the host of a switch becomes an snmpbulkwalk argument ─────────
    for good in ("10.0.0.2", "core-sw.lan", "sw1", "a.b-c.d"):
        check(p.valid_switch_host(good) is True, f"valid_switch_host: {good!r} is accepted")
    for bad in ("", "-v3", "--help", "-Cr10", "a b", "10.0.0.2;reboot", "sw$1", "sw_1 ", "x" * 256, ".lan", "lan-"):
        check(p.valid_switch_host(bad) is False, f"valid_switch_host: {bad[:20]!r} is refused")

    # ── 1.0.1: a switch belongs to the subnet its address is in ──────────────
    smap = {1: {"cidr": "10.1.0.0/24"}, 2: {"cidr": "10.2.0.0/24"}}
    check(p.derive_subnet_id("10.2.0.9", smap) == 2, "derive_subnet_id: an address in subnet 2")
    check(p.derive_subnet_id("172.16.0.1", smap) is None, "derive_subnet_id: an address in no subnet is None")
    check(p.derive_subnet_id("core-sw.lan", smap) is None, "derive_subnet_id: a hostname is None, never guessed")

    # ── a fake database and request, to run the impure code ──────────────────
    class FakeDB:
        def __init__(self, selects=None, rowcount=1):
            self.statements = []
            self.selects = list(selects or [])
            self.rowcount = rowcount

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.statements.append((sql.split()[0].upper(), sql, params))

        def fetchone(self):
            return self.selects.pop(0) if self.selects else None

        def fetchall(self):
            return self.selects.pop(0) if self.selects else []

        def commit(self):
            pass

        def close(self):
            pass

        def kinds(self):
            return [s[0] for s in self.statements]

    only_one = lambda sid: sid == 1  # noqa: E731 - a subnet-restricted caller: subnet 1; None is not theirs
    everything = lambda sid: True  # noqa: E731 - an unrestricted caller
    flashed = []
    p.flash = lambda msg, cat="message": flashed.append(msg)
    p.redirect = lambda where: "redirect"
    p.url_for = lambda *a, **k: "/x"
    p.jsonify = lambda payload: payload
    p._require_write = lambda: True
    p._subnet_map = lambda: smap
    jen_api = types.ModuleType("jen.plugin_api")
    jen_api.decrypt_secret = lambda s: s
    jen_api.normalize_mac = sys.modules["jen.plugin_api"].normalize_mac
    jen_api.like_pattern = sys.modules["jen.plugin_api"].like_pattern
    sys.modules["jen"] = types.ModuleType("jen")
    sys.modules["jen.plugin_api"] = jen_api
    sys.modules["jen"].plugin_api = jen_api

    # ── 1.0.1: switches are judged on their own address ──────────────────────
    for label, host in (("a switch in subnet 2", "10.2.0.2"), ("a switch addressed by hostname", "core-sw.lan")):
        for name, args in (("toggle_switch", (7,)), ("delete_switch", (7,)), ("set_uplink", (7, 12))):
            fdb = FakeDB([{"id": 7, "host": host, "enabled": 1}])
            p._get_db = lambda fdb=fdb: fdb
            p._can = only_one
            p.request = types.SimpleNamespace(form={"value": "up"})
            getattr(p, name)(*args)
            check(
                fdb.kinds() == ["SELECT"] and flashed[-1] == "Switch not found.",
                f"{name}: {label} reads as not found to a caller scoped to subnet 1 — nothing written",
            )
    fdb = FakeDB([{"id": 7, "host": "10.1.0.2", "enabled": 1}])
    p._get_db = lambda fdb=fdb: fdb
    p.set_uplink(7, 12)
    check("UPDATE" in fdb.kinds(), "set_uplink: a switch in the caller's own subnet can be changed")

    # ── 1.0.4: set_uplink validates `value` and does not claim success on 0 rows ──
    fdb = FakeDB([{"id": 7, "host": "10.1.0.2", "enabled": 1}])
    p._get_db = lambda fdb=fdb: fdb
    flashed.clear()
    p.request = types.SimpleNamespace(form={"value": "sideways"})
    p.set_uplink(7, 12)
    check(
        fdb.kinds() == ["SELECT"] and any("Pick one" in m for m in flashed),
        f"set_uplink: an unrecognised value is refused before any UPDATE (got {fdb.kinds()}, {flashed})",
    )
    fdb = FakeDB([{"id": 7, "host": "10.1.0.2", "enabled": 1}], rowcount=0)
    p._get_db = lambda fdb=fdb: fdb
    flashed.clear()
    p.request = types.SimpleNamespace(form={"value": "up"})
    p.set_uplink(7, 999)
    check(
        "UPDATE" in fdb.kinds() and any("not found on this switch" in m for m in flashed),
        f"set_uplink: a stale/garbled ifindex is refused, not reported as updated (got {flashed})",
    )

    # ── 1.0.4: community polling with no VLANs configured refuses, never wipes the switch ──
    # each of these three uses its OWN fresh module: they override _run_snmpbulkwalk/_fdb_positions/
    # _current_subnet_for_mac/_get_db, which the poll and search tests further down still depend on.
    fresh1 = load_plugin()
    switch_no_vlans = {"host": "10.1.0.2", "vlan_indexing": "community", "vlans": ""}
    try:
        fresh1._fdb_positions(switch_no_vlans, "public", {})
        raised = False
    except fresh1._PollError as e:
        raised = "VLAN" in str(e)
    check(raised, "_fdb_positions: community indexing with no VLANs configured raises _PollError, not {}")

    # ── 1.0.4: a DB failure recording a poll does not put its own text in a rendered column ──
    fresh2 = load_plugin()
    fresh2._run_snmpbulkwalk = lambda *a, **k: ""
    fresh2._fdb_positions = lambda *a, **k: {}
    recorded = []
    fresh2._record_poll_result = lambda switch_id, error: recorded.append(error)

    def db_down_poll(*a, **k):
        raise RuntimeError("Access denied for user 'jen'@'10.9.9.9' marker-q96")

    fresh2._get_db = db_down_poll
    fresh2._poll_switch({"id": 7, "name": "sw", "host": "10.1.0.2", "community": ""})
    check(
        recorded and "marker-q96" not in recorded[-1] and "10.9.9.9" not in recorded[-1],
        f"_poll_switch: a DB failure's own text never reaches sp_switches.last_error (got {recorded})",
    )

    # ── 1.0.4: the search provider raises the candidate pool without lowering the result cap ──
    fresh3 = load_plugin()
    many_rows = [{"mac": f"aa:bb:cc:dd:ee:{i:02x}", "switch_name": "s", "ifname": "Gi1"} for i in range(200)]
    fresh3._current_subnet_for_mac = lambda mac: 1
    fresh3._can = everything
    sql = None

    class _CapturingDB(FakeDB):
        def execute(self, sql_text, params=()):
            nonlocal sql
            sql = sql_text
            super().execute(sql_text, params)

    fresh3._get_db = lambda: _CapturingDB([list(many_rows)])
    got = fresh3._switchport_search("Gi", [], True)
    check("LIMIT 200" in sql, f"_switchport_search: the candidate pool is 200, not 20 (got {sql!r})")
    check(len(got) == 20, f"_switchport_search: still stops at 20 results (got {len(got)})")
    fdb = FakeDB([{"id": 7, "host": "core-sw.lan", "enabled": 1}])
    p._get_db = lambda fdb=fdb: fdb
    p._can = everything
    p.delete_switch(7)
    check("DELETE" in fdb.kinds(), "delete_switch: an unrestricted caller may remove a switch addressed by hostname")

    # ── 1.0.1: adding a switch validates the host and judges its subnet ──────
    for label, host, can in (
        ("an option-shaped host", "-v3", everything),
        ("a hostname, for a scoped caller", "core-sw.lan", only_one),
        ("an address in another subnet, for a scoped caller", "10.2.0.5", only_one),
    ):
        fdb = FakeDB()
        p._get_db = lambda fdb=fdb: fdb
        p._can = can
        p.request = types.SimpleNamespace(form={"name": "sw", "host": host, "vlan_indexing": "none"})
        p.add_switch()
        check(fdb.statements == [], f"add_switch: {label} is refused, nothing stored")
    fdb = FakeDB()
    p._get_db = lambda fdb=fdb: fdb
    p._can = only_one
    p.request = types.SimpleNamespace(form={"name": "sw", "host": "10.1.0.5", "vlan_indexing": "none"})
    p.add_switch()
    check("INSERT" in fdb.kinds(), "add_switch: an address in the caller's own subnet is accepted")

    # ── 1.0.1: the page lists only the switches the caller may see, with counts ─
    switches = [
        {"id": 1, "name": "mine", "host": "10.1.0.2", "vlan_indexing": "none", "vlans": None, "enabled": 1},
        {"id": 2, "name": "theirs", "host": "10.2.0.2", "vlan_indexing": "none", "vlans": None, "enabled": 1},
        {"id": 3, "name": "by-name", "host": "core-sw.lan", "vlan_indexing": "none", "vlans": None, "enabled": 1},
    ]
    ports = [
        {"ifindex": 1, "ifname": "Gi1", "ifalias": "", "is_uplink": None, "mac_count": 37},
        {"ifindex": 2, "ifname": "Gi2", "ifalias": "", "is_uplink": None, "mac_count": 1},
    ]
    for label, can, expected in (
        ("a scoped caller", only_one, ["mine"]),
        ("an unrestricted caller", everything, ["mine", "theirs", "by-name"]),
    ):
        fdb = FakeDB(
            [[dict(s) for s in switches], [dict(x) for x in ports], [dict(x) for x in ports], [dict(x) for x in ports]]
        )
        p._get_db = lambda fdb=fdb: fdb
        p._can = can
        rows = p._switch_rows()
        check(
            [s["name"] for s in rows] == expected,
            f"_switch_rows: {label} sees {expected} (got {[s['name'] for s in rows]})",
        )
    check(
        [x["uplink"] for x in rows[0]["ports"]] == [True, False],
        "_switch_rows: a port with 37 MACs is flagged an uplink, one with 1 is not — from the STORED count",
    )

    # ── 1.0.1: polling records every port's real MAC count, uplinks included ─
    IFINDEX = "".join(f".1.3.6.1.2.1.17.1.4.1.2.{n} = INTEGER: {10100 + n}\n" for n in (1, 2))
    NAMES = "".join(f'.1.3.6.1.2.1.31.1.1.1.1.{10100 + n} = STRING: "Gi{n}"\n' for n in (1, 2))
    ALIASES = "".join(f'.1.3.6.1.2.1.31.1.1.1.18.{10100 + n} = STRING: ""\n' for n in (1, 2))
    fdb_lines = [f".1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.0.0.0.0.{n} = INTEGER: 1\n" for n in range(1, 10)]  # 9 MACs, port 1
    fdb_lines.append(".1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.0.0.0.1.1 = INTEGER: 2\n")  # 1 MAC, port 2
    walks = {
        p.OID_DOT1D_BASE_PORT_IFINDEX: IFINDEX,
        p.OID_IF_NAME: NAMES,
        p.OID_IF_ALIAS: ALIASES,
        p.OID_DOT1Q_TP_FDB_PORT: "".join(fdb_lines),
    }
    p._run_snmpbulkwalk = lambda host, community, oid, timeout=20: walks[oid]
    fdb = FakeDB([[], [], []])  # port overrides, old positions, previously-here rows
    p._get_db = lambda: fdb
    p._poll_switch({"id": 4, "name": "s", "host": "10.1.0.2", "community": "", "vlan_indexing": "none", "vlans": None})
    stored = {s[2][1]: s[2][4] for s in fdb.statements if s[0] == "INSERT" and "sp_ports" in s[1]}
    check(
        stored == {10101: 9, 10102: 1},
        f"_poll_switch: the uplink-shaped port stores its 9 MACs, the desk port its 1 (got {stored})",
    )
    located_inserts = [s for s in fdb.statements if s[0] == "INSERT" and "sp_mac_ports" in s[1]]
    check(len(located_inserts) == 1, "_poll_switch: only the MAC NOT behind the auto-detected uplink is located")

    # ── 1.0.1: a move sends the alert, in the MAC's own subnet, and the event ─
    sent, emitted = [], []
    jen_api.send_alert = lambda alert_type, subnet_id=None, **kw: sent.append((alert_type, subnet_id, kw))
    jen_api.emit = lambda kind, **kw: emitted.append((kind, kw))
    p._port_label = lambda switch_id, ifindex: f"sw{switch_id}:{ifindex}"
    p._current_subnet_for_mac = lambda mac: 1
    p._emit_move("aa:bb:cc:dd:ee:ff", (1, 12), (2, 7))
    check(
        sent == [("switchport_moved", 1, {"mac": "aa:bb:cc:dd:ee:ff", "old": "sw1:12", "new": "sw2:7"})],
        f"_emit_move: sends switchport_moved for the MAC's own subnet (got {sent})",
    )
    check(emitted and emitted[0][0] == "plugin.switchport.moved", "_emit_move: still emits the Timeline event")

    # ── 1.0.1: the locate API — a MAC with no subnet is for an unrestricted key only ─
    def key_can(key, subnet_id, *, allow_unattributed=False):
        scope = key.get("subnet_ids")
        if scope is None:
            return True
        return subnet_id is not None and subnet_id in scope

    jen_api.api_key_can_access_subnet = key_can
    p._locate_mac = lambda mac: None
    for label, sid, key, expect in (
        ("a scoped key, MAC in its subnet", 1, {"subnet_ids": [1]}, "ok"),
        ("a scoped key, MAC in another subnet", 2, {"subnet_ids": [1]}, 403),
        ("a scoped key, MAC with no subnet", None, {"subnet_ids": [1]}, 403),
        ("an unrestricted key, MAC with no subnet", None, {"subnet_ids": None}, "ok"),
    ):
        p._current_subnet_for_mac = lambda mac, sid=sid: sid
        sys.modules["flask"].g = types.SimpleNamespace(api_key=key)
        result = p._api_locate("aa:bb:cc:dd:ee:01")
        got = result[1] if isinstance(result, tuple) else "ok"
        check(got == expect, f"_api_locate: {label} -> {expect}")

    # ── 1.0.1: the search provider returns the MAC's REAL subnet ─────────────
    rows = [
        {"mac": "aa:bb:cc:dd:ee:01", "switch_name": "s", "ifname": "Gi1"},
        {"mac": "aa:bb:cc:dd:ee:02", "switch_name": "s", "ifname": "Gi2"},
        {"mac": "aa:bb:cc:dd:ee:03", "switch_name": "s", "ifname": "Gi3"},
    ]
    subnet_of = {"aa:bb:cc:dd:ee:01": 1, "aa:bb:cc:dd:ee:02": 2, "aa:bb:cc:dd:ee:03": None}
    p._current_subnet_for_mac = lambda mac: subnet_of[mac]
    for label, can, expected in (
        ("a scoped caller", only_one, {"aa:bb:cc:dd:ee:01": 1}),
        (
            "an unrestricted caller",
            everything,
            {"aa:bb:cc:dd:ee:01": 1, "aa:bb:cc:dd:ee:02": 2, "aa:bb:cc:dd:ee:03": None},
        ),
    ):
        p._get_db = lambda: FakeDB([list(rows)])
        p._can = can
        got = {r["title"]: r["subnet_id"] for r in p._switchport_search("Gi", [], False)}
        check(got == expected, f"_switchport_search: {label} gets {expected} (got {got})")

    # ── 1.0.3: a database failure never reaches the page ─────────────────────
    def db_down(*a, **k):
        raise RuntimeError("Access denied for user 'jen'@'10.9.9.9' marker-q96")

    flashed.clear()
    p._can = everything
    p._get_db = db_down
    p.request = types.SimpleNamespace(form={"name": "x", "host": "10.1.0.5", "vlan_indexing": "none"}, args={})
    p.add_switch()
    check(
        flashed and all("marker-q96" not in m and "10.9.9.9" not in m for m in flashed) and "Jen's log" in flashed[-1],
        f"add_switch: a database failure shows a generic message and no exception text (got {flashed})",
    )

    # ── 1.0.3: the MAC's subnet is Jen's ONE precedence ──────────────────────
    api = types.ModuleType("jen.plugin_api")
    api.client_subnet_for_mac = lambda mac: {"aa:bb:cc:dd:ee:09": 4}.get(mac)
    sys.modules["jen"] = types.ModuleType("jen")
    sys.modules["jen.plugin_api"] = api
    sys.modules["jen"].plugin_api = api
    fresh = load_plugin()
    check(
        fresh._current_subnet_for_mac("aa:bb:cc:dd:ee:09") == 4
        and fresh._current_subnet_for_mac("aa:bb:cc:dd:ee:10") is None,
        "_current_subnet_for_mac: answered by plugin_api.client_subnet_for_mac, not a private copy",
    )

    # ── register(): runs end to end against a stub that enforces Jen's rules ──
    calls = _stub_jen_plugin_api()
    try:
        p.register(_FakeApp())
        registered = True
    except Exception as e:
        registered = False
        print(f"      register() raised: {e}")
    check(registered, "register(): runs end to end without raising against a real-rule stub")
    check(
        calls["alert_types"] == ["switchport_moved"],
        f"register(): the moved alert type is registered under the plugin's own prefix (got {calls['alert_types']})",
    )
    check(
        calls["periodic"] == [("switchport", "poll", 10)],
        f"register(): the poll runs every 10 minutes (got {calls['periodic']})",
    )
    check(
        len(calls["row_actions"]) == 3 and len(calls["search"]) == 1,
        "register(): three row actions and one search provider",
    )
    check(
        len(calls["investigation"]) == 1
        and calls["investigation"][0][0] == ("switchport",)
        and calls["investigation"][0][1]["fn"] is p._investigate,
        "register(): exactly one investigation provider, the plugin's own",
    )

    # ── 1.1.0: the investigation provider ────────────────────────────────────
    check(
        p.in_scope(1, [1], False) and not p.in_scope(2, [1], False) and not p.in_scope(None, [1], False),
        "in_scope: a restricted caller sees only its own subnets, and None is never allow",
    )
    check(p.in_scope(None, [], True), "in_scope: an unrestricted caller sees an unattributed MAC")
    check(p.investigation_card([]) is None, "investigation_card: a MAC never located adds no card")
    here = {
        "switch_name": "sw1", "host": "10.1.0.2", "ifindex": 3, "ifname": "Gi1/0/3", "ifalias": "desk 12", "is_uplink": None,
        "mac_count": 1, "vlan": 20, "first_seen": None, "last_seen": None,
    }  # fmt: skip
    card = p.investigation_card([here])
    check(
        card["status"] == "ok"
        and "sw1" in card["summary"]
        and "Gi1/0/3" in card["summary"]
        and "VLAN 20" in card["summary"],
        f"investigation_card: the switch, port and VLAN in the summary (got {card['summary']!r})",
    )
    check(
        {"label": "Port", "value": "Gi1/0/3 - desk 12"} in card["rows"],
        "investigation_card: the port row carries the alias",
    )
    old = dict(here, switch_name="sw0", ifname="Gi0/9")
    moved = p.investigation_card([here, old])
    check(
        "moved" in moved["summary"] and "sw0" in moved["summary"] and moved["status"] == "ok",
        f"investigation_card: a second switch's older position reads as a move (got {moved['summary']!r})",
    )
    pinned = p.investigation_card([dict(here, is_uplink=1)])
    check(
        pinned["status"] == "warn" and "uplink" in pinned["summary"],
        "investigation_card: a port now treated as an uplink is a warn card",
    )
    crowded = p.investigation_card([dict(here, mac_count=40)])
    check(crowded["status"] == "warn", "investigation_card: past the MAC-count threshold is an uplink too")
    unpinned = p.investigation_card([dict(here, is_uplink=0, mac_count=40)])
    check(unpinned["status"] == "ok", "investigation_card: a hand pin to NOT an uplink beats the count")

    # ── 1.1.1: each STORED position is judged by its OWN switch's subnet (the one its address is in) ──
    import datetime as _dt

    smap = {1: {"cidr": "10.1.0.0/24"}, 2: {"cidr": "10.2.0.0/24"}}
    in_b = dict(
        here,
        switch_name="sw-b",
        host="10.2.0.9",
        ifname="Gi2/0/1",
        ifalias="",
        last_seen=_dt.datetime(2026, 10, 2, 9, 30),
    )
    in_a = dict(here, switch_name="sw-a", host="10.1.0.2", ifname="Gi1/0/3")
    by_name = dict(here, switch_name="sw-name", host="core-sw.lan")
    vis, hidden = p.positions_in_scope([in_a], smap, [1], False)
    check(
        vis == [in_a] and hidden is False,
        "positions_in_scope: a position on a switch in the caller's subnet is visible",
    )
    vis, hidden = p.positions_in_scope([in_b], smap, [1], False)
    check(
        vis == [] and hidden is True,
        "positions_in_scope: a position on a switch in another subnet is not, and the newest was hidden",
    )
    vis, hidden = p.positions_in_scope([in_b, in_a], smap, [1], False)
    check(
        vis == [in_a] and hidden is True,
        "positions_in_scope: a mix keeps only the visible position, and says the newest one was hidden",
    )
    vis, hidden = p.positions_in_scope([in_a, in_b], smap, [1], False)
    check(
        vis == [in_a] and hidden is False,
        "positions_in_scope: an older hidden position does not make the newest 'hidden'",
    )
    check(
        p.positions_in_scope([by_name], smap, [1], False)[0] == []
        and p.positions_in_scope([by_name], smap, [], True)[0] == [by_name],
        "positions_in_scope: a switch addressed by hostname has no subnet - unrestricted callers only, never read as allow",
    )
    check(
        p.positions_in_scope([in_b, in_a], smap, [1, 2], False)[0] == [in_b, in_a]
        and p.positions_in_scope([in_b, in_a], smap, [], True) == ([in_b, in_a], False),
        "positions_in_scope: a caller who may see both switches, or every subnet, sees every position",
    )
    last = p.investigation_card([in_a], newest_hidden=True)
    check(
        last["summary"].startswith("Last seen on sw-a") and "moved" not in last["summary"],
        f"investigation_card: when the newest position was hidden the card says 'last seen', not 'on' (got {last['summary']!r})",
    )
    stamped = p.investigation_card([dict(in_a, last_seen=_dt.datetime(2026, 10, 1, 7, 0))], newest_hidden=True)
    check("at 2026-10-01 07:00 UTC" in stamped["summary"], "investigation_card: 'last seen' carries its time")
    check(
        "moved" not in p.investigation_card([in_a, dict(old, host="10.1.0.5")], newest_hidden=True)["summary"],
        "investigation_card: no claim about a move when the newest position is not shown",
    )

    # the impure provider, end to end through the plugin's own query and scope check
    subject = types.SimpleNamespace(mac="AA:BB:CC:DD:EE:01")
    p._current_subnet_for_mac = lambda mac: 1
    p._subnet_map = lambda: smap
    fdb = FakeDB([[dict(here)]])
    p._get_db = lambda: fdb
    got = p._investigate(subject, [1], False)
    check(
        got is not None and got["href"] == "/network/switchport?mac=aa:bb:cc:dd:ee:01" and "sw1" in got["summary"],
        f"_investigate: the card for a seeded client, linking to the plugin's own page (got {got})",
    )
    check(
        "mp.mac=%s" in fdb.statements[0][1] and fdb.statements[0][2] == ("aa:bb:cc:dd:ee:01",),
        "_investigate: the lookup is the one parameterised MAC query",
    )
    p._get_db = lambda: FakeDB([[]])
    check(p._investigate(subject, [1], False) is None, "_investigate: an unknown client gets None")
    # the leak direction: stored on a switch in B, the client has since moved to A - a caller scoped to A must NOT see it
    p._get_db = lambda: FakeDB([[dict(in_b)]])
    check(
        p._investigate(subject, [1], False) is None,
        "_investigate: a client whose only positions are on switches in B gets no card for a caller scoped to A, wherever it is now",
    )
    p._get_db = lambda: FakeDB([[dict(in_b)]])
    check(
        p._investigate(subject, [1, 2], False) is not None and p._investigate(subject, [], True) is not None,
        "_investigate: the same position is shown to a caller who may see B, and to an unrestricted one",
    )
    p._get_db = lambda: FakeDB([[dict(in_b), dict(in_a)]])
    mixed = p._investigate(subject, [1], False)
    check(
        mixed is not None
        and "sw-b" not in str(mixed)
        and "Gi2/0/1" not in str(mixed)
        and mixed["summary"].startswith("Last seen on sw-a"),
        f"_investigate: a mix shows only the visible switch, as 'last seen' because the newest was hidden (got {mixed})",
    )
    p._get_db = lambda: FakeDB([[dict(in_a), dict(in_b)]])
    older_hidden = p._investigate(subject, [1], False)
    check(
        older_hidden is not None
        and older_hidden["summary"].startswith("On sw-a")
        and "sw-b" not in str(older_hidden)
        and "moved" not in older_hidden["summary"],
        f"_investigate: the newest visible, an older one hidden: 'on', no move claim, no hidden name (got {older_hidden})",
    )
    p._get_db = lambda: FakeDB([[dict(in_b, ifname=f"Gi9/0/{i}") for i in range(6)] + [dict(in_a)]])
    check(
        p._investigate(subject, [1], False) is not None,
        "_investigate: six hidden positions do not push a visible one out of the card (the LIMIT comes after the scope)",
    )
    p._get_db = lambda: FakeDB([[dict(by_name)]])
    check(
        p._investigate(subject, [1], False) is None and p._investigate(subject, [], True) is not None,
        "_investigate: a switch addressed by hostname is for an unrestricted caller only",
    )
    p._current_subnet_for_mac = lambda mac: None  # the client's own subnet no longer decides anything
    p._get_db = lambda: FakeDB([[dict(here)]])
    check(
        p._investigate(subject, [1], False) is not None,
        "_investigate: where the client is now neither widens nor narrows what its stored positions show",
    )
    check(
        p._investigate(types.SimpleNamespace(mac=""), [1], True) is None
        and p._investigate(types.SimpleNamespace(mac="not-a-mac"), [1], True) is None,
        "_investigate: a subject with no (or an invalid) MAC gets None",
    )

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
