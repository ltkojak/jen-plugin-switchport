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

    flask.Blueprint = Blueprint
    for name in ("flash", "jsonify", "make_response", "redirect", "render_template", "url_for"):
        setattr(flask, name, lambda *a, **k: None)
    flask.request = None
    sys.modules["flask"] = flask
    fl = types.ModuleType("flask_login")
    fl.current_user = types.SimpleNamespace(username="tester", all_subnets=True, role="admin")
    fl.login_required = lambda fn: fn
    sys.modules["flask_login"] = fl


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

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
