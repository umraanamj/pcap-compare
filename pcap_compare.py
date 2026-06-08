#!/usr/bin/env python3
"""
PCAP Compare — Zscaler ZPA "Network Presence" coverage finder.

The problem this solves
-----------------------
ZPA Network Presence only lets an app reach the exact IPs / FQDNs you've listed
in its Application Segment. App owners rarely know the full list, so connections
to anything missing just fail. This script finds what's missing.

  GOOD endpoint capture = taken in the office with ZPA / VPN OFF (full
                 connectivity). GROUND TRUTH of every destination the app uses.
  BAD  endpoint capture = taken with ZPA / Network Presence ON. The app can only
                 reach what's in the segment, so the gaps show up as failures.
  App Connector capture (OPTIONAL) = taken at the network connector that brokers
                 the conversation (Client -> Service Edge -> App Connector ->
                 server). Lets the tool say WHERE a flow breaks: before the
                 connector (broker / Network Presence) or behind it (app side).

The script enumerates every destination the app talks to in the GOOD capture,
then reports which ones FAIL or never appear in the BAD capture — i.e. the
IPs/FQDNs you need to add to the Application Segment. With a connector capture it
also traces each failing flow to a break point.

Launch flow: a file picker for the GOOD capture, the BAD capture, then an
OPTIONAL App Connector capture (cancel to skip). On macOS the picker is the
native dialog (osascript) so no tkinter is needed; other platforms use tkinter,
falling back to a terminal prompt. You can also pass the files on the command
line (the connector is optional):

    python3 pcap_compare.py GOOD.pcap BAD.pcap [CONNECTOR.pcap]

Works with .pcap and .pcapng (tshark autodetects).

Key design choices
------------------
  * Destinations are matched by FQDN, NOT IP. With ZPA on, DNS resolves through
    Zscaler and often returns different/synthetic IPs, so the same FQDN has
    different IPs in the two captures. FQDNs come from DNS queries, TLS SNI, and
    HTTP Host headers.
  * Two failure modes are distinguished in the BAD capture:
      - DNS never resolves the name      -> ZPA doesn't know the FQDN at all
      - resolves but SYN gets no SYN-ACK  -> not covered by the segment / blocked
  * The App Connector source-NATs the client, so connector flows are correlated
    by DESTINATION too — and the connector talks to the REAL server IPs, the same
    ones seen in the GOOD capture, so IP matching lines up across the broker. The
    client source IP is still extracted and shown (and used if it happens to be
    preserved at the connector).

Requires Wireshark's `tshark` on PATH (or in the macOS Wireshark.app bundle).
  macOS:  brew install --cask wireshark
"""

import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict

# Single-pass tshark field list. Order maps to the indices used in parse_capture.
TSHARK_FIELDS = [
    "frame.time_relative",                   # 0
    "tcp.stream",                            # 1
    "ip.src",                               # 2
    "ip.dst",                               # 3
    "tcp.dstport",                          # 4
    "tcp.flags.syn",                        # 5
    "tcp.flags.ack",                        # 6
    "tcp.flags.reset",                      # 7
    "tcp.len",                              # 8
    "tls.handshake.extensions_server_name",  # 9  SNI
    "http.host",                            # 10 HTTP Host header
    "dns.flags.response",                   # 11 1 = this packet is a response
    "dns.qry.name",                         # 12 queried name
    "dns.a",                                # 13 A answers (comma-joined)
    "dns.aaaa",                             # 14 AAAA answers
    "dns.flags.rcode",                      # 15 0 = ok, 3 = NXDOMAIN, etc.
]

# Vendors whose traffic we deliberately IGNORE for now (telemetry / CDN noise the
# app doesn't depend on). Matched by FQDN suffix. Edit these lists to taste.
IGNORED_VENDORS = {
    "Microsoft": (
        "microsoft.com", "microsoftonline.com", "windows.com", "windowsupdate.com",
        "office.com", "office.net", "office365.com", "live.com", "outlook.com",
        "msn.com", "bing.com", "azure.com", "azureedge.net", "azurewebsites.net",
        "windows.net", "msftncsi.com", "msftconnecttest.com", "msedge.net",
        "msecnd.net", "msauth.net", "msftauth.net", "sharepoint.com",
        "onedrive.com", "skype.com", "xboxlive.com", "trafficmanager.net",
        "s-microsoft.com",
    ),
    "Google": (
        "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
        "ggpht.com", "googlevideo.com", "gvt1.com", "gvt2.com", "gvt3.com",
        "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
        "doubleclick.net", "youtube.com", "ytimg.com", "googlemail.com",
        "gmail.com", "android.com",
    ),
}


def ignored_vendor(fqdn):
    """Return the vendor name if this FQDN belongs to an ignored vendor, else None."""
    if not fqdn:
        return None
    f = fqdn.rstrip(".").lower()
    for vendor, suffixes in IGNORED_VENDORS.items():
        if any(f == s or f.endswith("." + s) for s in suffixes):
            return vendor
    return None


def _windows_tshark_candidates():
    """Likely tshark.exe locations on Windows (env vars + registry, no hardcoding)."""
    candidates = []
    for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        base = os.environ.get(var)
        if base:
            candidates.append(os.path.join(base, "Wireshark", "tshark.exe"))
    # The Wireshark installer records its install dir in the registry.
    try:
        import winreg
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, r"SOFTWARE\Wireshark") as key:
                    install_dir = winreg.QueryValueEx(key, "InstallDir")[0]
                    candidates.append(os.path.join(install_dir, "tshark.exe"))
            except OSError:
                pass
    except Exception:
        pass
    return candidates


def find_tshark():
    """Locate tshark on PATH or in a standard Wireshark install, per-OS."""
    # 1. Already on PATH? (works everywhere)
    path = shutil.which("tshark") or shutil.which("tshark.exe")
    if path:
        return path
    # 2. Wireshark is often not on PATH — check OS-specific install locations.
    if sys.platform.startswith("win"):
        candidates = _windows_tshark_candidates()
    elif sys.platform == "darwin":
        candidates = ["/Applications/Wireshark.app/Contents/MacOS/tshark"]
    else:
        candidates = ["/usr/bin/tshark", "/usr/local/bin/tshark"]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def _pick_with_osascript(title):
    """Native macOS open dialog via osascript — needs no tkinter/Tk."""
    prompt = title.replace('"', "'")
    script = (
        'POSIX path of (choose file with prompt "%s" '
        'of type {"pcap", "pcapng", "cap"})' % prompt
    )
    proc = subprocess.run(["osascript", "-e", script],
                          capture_output=True, text=True)
    if proc.returncode != 0:        # user cancelled (-128) or no selection
        return None
    return proc.stdout.strip() or None


def _pick_with_tkinter(title):
    """Tk file dialog. Returns (available, path). available=False if no Tk."""
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception:
        return False, None
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askopenfilename(
        title=title,
        filetypes=[
            ("Capture files", "*.pcap *.pcapng *.cap"),
            ("All files", "*.*"),
        ],
    )
    root.destroy()
    return True, (path or None)


def select_pcap_file(title):
    """Pick a capture file: native dialog on macOS, Tk elsewhere, then prompt."""
    if sys.platform == "darwin":
        return _pick_with_osascript(title)
    available, path = _pick_with_tkinter(title)
    if available:
        return path
    # Headless / no Tk: fall back to a terminal prompt.
    try:
        entered = input(f"{title}\n  path> ").strip()
    except EOFError:
        return None
    return entered or None


def _pick_multi_with_osascript(title):
    """Native macOS open dialog allowing multiple selections (POSIX paths)."""
    prompt = title.replace('"', "'")
    script = (
        'set theFiles to choose file with prompt "%s" '
        'of type {"pcap", "pcapng", "cap"} with multiple selections allowed\n'
        'set out to ""\n'
        'repeat with f in theFiles\n'
        'set out to out & POSIX path of f & linefeed\n'
        'end repeat\n'
        'return out' % prompt
    )
    proc = subprocess.run(["osascript", "-e", script],
                          capture_output=True, text=True)
    if proc.returncode != 0:        # cancelled
        return []
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


def _pick_multi_with_tkinter(title):
    """Tk multi-select dialog. Returns (available, [paths])."""
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception:
        return False, []
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    paths = filedialog.askopenfilenames(
        title=title,
        filetypes=[
            ("Capture files", "*.pcap *.pcapng *.cap"),
            ("All files", "*.*"),
        ],
    )
    root.destroy()
    return True, list(paths)


def select_pcap_files(title):
    """Pick one or more capture files. Returns a (possibly empty) list of paths."""
    if sys.platform == "darwin":
        return _pick_multi_with_osascript(title)
    available, paths = _pick_multi_with_tkinter(title)
    if available:
        return paths
    # Headless fallback: accept a single path (blank = none).
    try:
        entered = input(f"{title}\n  path (blank to skip)> ").strip()
    except EOFError:
        return []
    return [entered] if entered else []


class StreamStat:
    """Per-TCP-stream rollup used to decide if a connection succeeded."""

    def __init__(self):
        self.client_ip = None   # source of the SYN — the endpoint making the request
        self.server_ip = None
        self.server_port = None
        self.ips_seen = set()   # every IP seen in this stream (src or dst, both dirs)
        self.syn = False
        self.syn_ack = False
        self.rst = False
        self.server_bytes = 0   # payload bytes sent BY the server (proof it answered)
        self.sni = None
        self.host = None

    def outcome(self):
        """ok | reset | no_response | half_open | unknown."""
        if self.syn_ack and self.server_bytes > 0:
            return "ok"
        if self.syn and not self.syn_ack:
            return "no_response"
        if self.syn_ack and self.rst:
            return "reset"
        if self.syn_ack:
            return "half_open"
        return "unknown"


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _truthy(v):
    """tshark prints boolean fields as '1' or 'True' depending on version."""
    return v in ("1", "True", "true")


def _ips(field):
    """A tshark ip.src/ip.dst field may hold several comma-joined IPs when the
    packet is tunnelled/encapsulated (outer + inner). Return them as a list."""
    return [x for x in field.split(",") if x]


def parse_capture(tshark, path):
    """Run one tshark pass and fold rows into a destination-centric profile."""
    cmd = [tshark, "-r", path, "-T", "fields", "-E", "separator=\t"]
    for fld in TSHARK_FIELDS:
        cmd += ["-e", fld]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"tshark failed on {path}")

    streams = defaultdict(StreamStat)
    dns_answers = defaultdict(set)   # fqdn -> {resolved IPs}
    dns_resolved = set()             # fqdns that got at least one good answer
    dns_failed = set()               # fqdns queried but NXDOMAIN / no answer
    dns_queried = set()              # every fqdn the client asked about
    dns_query_src = Counter()        # src IP -> # of DNS queries it issued
    all_src_counts = Counter()       # every packet's IP source (incl. UDP) -> count
    all_dst_counts = Counter()       # every packet's IP destination (incl. UDP)
    tunneled_rows = 0                # packets whose IP field held >1 IP (encap)
    tunneled_examples = []           # a few raw joined fields, for diagnostics
    total_packets = 0

    for line in proc.stdout.splitlines():
        if not line:
            continue
        total_packets += 1
        cols = line.split("\t")
        if len(cols) < len(TSHARK_FIELDS):
            cols += [""] * (len(TSHARK_FIELDS) - len(cols))

        src_ips = _ips(cols[2])
        dst_ips = _ips(cols[3])
        if "," in cols[2] or "," in cols[3]:
            tunneled_rows += 1
            if len(tunneled_examples) < 5:
                tunneled_examples.append(f"{cols[2]} -> {cols[3]}")
        # Primary src/dst = the INNERMOST IP. tshark lists encapsulated IPs
        # outer-first, inner-last, and for a tunnelled capture the inner packet
        # (endpoint -> app server) is the real conversation we want to analyze —
        # not the outer tunnel endpoints. ips_seen below keeps ALL layers so the
        # source IP still matches whether it's inner or outer.
        ip_src = src_ips[-1] if src_ips else ""
        ip_dst = dst_ips[-1] if dst_ips else ""
        dstport = cols[4]
        for ip in src_ips:
            all_src_counts[ip] += 1
        for ip in dst_ips:
            all_dst_counts[ip] += 1
        syn = _truthy(cols[5])
        ack = _truthy(cols[6])
        rst = _truthy(cols[7])
        tcp_len = int(_f(cols[8]) or 0)
        sni = cols[9].strip().lower() or None
        host = cols[10].strip().lower() or None
        dns_is_resp = _truthy(cols[11])
        dns_name = cols[12].strip().lower() or None
        dns_a = [x for x in cols[13].split(",") if x]
        dns_aaaa = [x for x in cols[14].split(",") if x]
        dns_rcode = cols[15]

        # --- DNS bookkeeping -------------------------------------------------
        if dns_name:
            dns_queried.add(dns_name)
            if not dns_is_resp and ip_src:
                # Who is asking — the endpoint host issuing the lookup.
                dns_query_src[ip_src] += 1
            if dns_is_resp:
                ips = dns_a + dns_aaaa
                if ips:
                    dns_answers[dns_name].update(ips)
                    dns_resolved.add(dns_name)
                elif dns_rcode and dns_rcode != "0":
                    dns_failed.add(dns_name)
                elif dns_rcode == "0" and not ips:
                    # NOERROR but no A/AAAA (e.g. only CNAME, or empty answer)
                    dns_failed.add(dns_name)

        # --- TCP stream bookkeeping -----------------------------------------
        stream_id = cols[1]
        if stream_id == "":
            continue
        s = streams[stream_id]
        s.ips_seen.update(src_ips)
        s.ips_seen.update(dst_ips)

        # Identify the server from the SYN (syn & !ack -> dst is the server).
        if syn and not ack:
            s.syn = True
            s.client_ip = ip_src
            s.server_ip = ip_dst
            s.server_port = dstport
        if syn and ack:
            s.syn_ack = True
            # SYN-ACK comes FROM the server; recover its IP if we missed the SYN.
            # (Port is taken from the SYN or the data-packet fallback below, since
            #  dstport on a SYN-ACK is the client's port, not the server's.)
            if s.server_ip is None:
                s.server_ip = ip_src
        if rst:
            s.rst = True
        if sni and not s.sni:
            s.sni = sni
        if host and not s.host:
            s.host = host
        # Server-origin payload = proof the far end actually responded with data.
        if s.server_ip and ip_src == s.server_ip and tcp_len > 0:
            s.server_bytes += tcp_len
        # Fallback server identity if we never saw a SYN at all.
        if s.server_ip is None and not syn:
            s.server_ip = ip_dst
            s.server_port = dstport

    # Build ip -> fqdn reverse map for this capture (its own DNS view).
    ip_fqdn = defaultdict(set)
    for fqdn, ips in dns_answers.items():
        for ip in ips:
            ip_fqdn[ip].add(fqdn)

    # Source IPs that originated connections (the endpoints making requests).
    client_ips = Counter(s.client_ip for s in streams.values() if s.client_ip)
    all_src_ips = set(client_ips)

    return {
        "path": path,
        "total_packets": total_packets,
        "streams": dict(streams),
        "dns_answers": dict(dns_answers),
        "dns_resolved": dns_resolved,
        "dns_failed": dns_failed,
        "dns_queried": dns_queried,
        "ip_fqdn": dict(ip_fqdn),
        "client_ips": client_ips,      # Counter: src IP -> #connections initiated
        "all_src_ips": all_src_ips,    # every source IP seen originating a SYN
        "dns_query_src": dns_query_src,  # Counter: src IP -> #DNS queries issued
        "all_src_counts": all_src_counts,  # per-packet IP source counts (incl. UDP)
        "all_dst_counts": all_dst_counts,  # per-packet IP destination counts
        "tunneled_rows": tunneled_rows,
        "tunneled_examples": tunneled_examples,
    }


def build_destinations(profile, only_involving_ips=None):
    """
    Collapse streams into destinations keyed by (fqdn, port) when an FQDN is
    known, else (ip, port). Returns {key: {fqdn, ips, port, outcome, n}}.

    If only_involving_ips is given, only streams in which one of those IPs appears
    (as source OR destination, either direction) are counted — used to scope a
    connector capture to a specific endpoint source IP.
    """
    rank = {"ok": 3, "half_open": 2, "reset": 1, "no_response": 0, "unknown": 0}
    dests = {}
    for s in profile["streams"].values():
        if only_involving_ips is not None and not (s.ips_seen & only_involving_ips):
            continue
        if not s.server_ip:
            continue
        # Best FQDN for this stream: SNI > Host > reverse-DNS of the server IP.
        fqdn = s.sni or s.host
        if not fqdn:
            names = profile["ip_fqdn"].get(s.server_ip)
            if names:
                fqdn = sorted(names)[0]
        key = (fqdn, s.server_port) if fqdn else (s.server_ip, s.server_port)

        oc = s.outcome()
        d = dests.get(key)
        if d is None:
            d = {"fqdn": fqdn, "ips": set(), "port": s.server_port,
                 "outcome": oc, "n": 0}
            dests[key] = d
        d["ips"].add(s.server_ip)
        d["n"] += 1
        # Keep the BEST outcome we saw for this destination.
        if rank[oc] > rank[d["outcome"]]:
            d["outcome"] = oc
    return dests


def _parent_domain(fqdn):
    """Rough registrable-domain guess for wildcard-segment suggestions."""
    parts = fqdn.split(".")
    if len(parts) <= 2:
        return fqdn
    # Handle common 2-label TLDs (co.uk, com.au, ...) lightly.
    two_label_tld = {"co.uk", "com.au", "co.jp", "co.nz", "com.br", "co.za"}
    if ".".join(parts[-2:]) in two_label_tld and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


_OUTCOME_RANK = {"ok": 3, "half_open": 2, "reset": 1, "no_response": 0, "unknown": 0}


def _merge_dests(dest_dicts):
    """Merge several destination sets, keeping the BEST outcome per destination
    and unioning the IPs (used to fold multiple App Connector captures into one)."""
    merged = {}
    for dd in dest_dicts:
        for key, d in dd.items():
            m = merged.get(key)
            if m is None:
                merged[key] = {"fqdn": d["fqdn"], "ips": set(d["ips"]),
                               "port": d["port"], "outcome": d["outcome"],
                               "n": d["n"]}
                continue
            m["ips"] |= d["ips"]
            m["n"] += d["n"]
            if _OUTCOME_RANK[d["outcome"]] > _OUTCOME_RANK[m["outcome"]]:
                m["outcome"] = d["outcome"]
            if not m["fqdn"] and d["fqdn"]:
                m["fqdn"] = d["fqdn"]
    return merged


def _index_dests(dests):
    """Index a destination set by (fqdn, port) and (ip, port) for fast lookup."""
    by_fqdn, by_ip = {}, {}
    for (_, port), d in dests.items():
        if d["fqdn"]:
            by_fqdn[(d["fqdn"], port)] = d
        for ip in d["ips"]:
            by_ip[(ip, port)] = d
    return by_fqdn, by_ip


def _lookup_dest(d, by_fqdn, by_ip):
    """Find this destination in another capture, by FQDN first then by IP."""
    if d["fqdn"]:
        hit = by_fqdn.get((d["fqdn"], d["port"]))
        if hit:
            return hit
    for ip in d["ips"]:
        if (ip, d["port"]) in by_ip:
            return by_ip[(ip, d["port"])]
    return None


def _connector_trace(d, conn_dns_failed, conn_by_fqdn, conn_by_ip):
    """
    Given a destination that failed for the client, say where it broke relative
    to the App Connector(s). Returns a one-line trace string, or None if unknown.

    App Connectors source-NAT the client, so we correlate by DESTINATION
    (FQDN/IP+port) — the same key the connection uses on both sides of the broker.
    Multiple connector captures are merged first (best outcome wins), so this is
    "did ANY connector broker it successfully".
    """
    conn_d = _lookup_dest(d, conn_by_fqdn, conn_by_ip)
    if conn_d is None:
        # No connector even tried this destination.
        if d["fqdn"] and d["fqdn"] in conn_dns_failed:
            return ("App Connector tried to resolve it and DNS FAILED there "
                    "→ fix DNS at the connector / app side")
        return ("never reached any App Connector → broker didn't route it "
                "(Network Presence / App Segment doesn't cover this destination)")
    if conn_d["outcome"] == "ok":
        return ("App Connector reached the server FINE → the break is between "
                "the client and the connector (broker / return path), not the app")
    if conn_d["outcome"] == "no_response":
        return ("reached the App Connector, but the server gave NO SYN-ACK to "
                "the connector → app unreachable behind the connector "
                "(firewall / routing / app down)")
    if conn_d["outcome"] == "reset":
        return ("reached the App Connector, but the server RESET it → app-side "
                "block behind the connector")
    if conn_d["outcome"] == "half_open":
        return ("reached the App Connector, connected but server sent no data "
                "→ app-side issue behind the connector")
    return "reached the App Connector, outcome unclear there"


def _source_ip_flows(prof, endpoint_ips):
    """
    Every TCP stream that involves one of the endpoint IPs, aggregated into
    (role, peer_ip, port, outcome, fqdn) -> count.

    role:  OUT = the endpoint IP initiates (it's the SYN source)
           IN  = something targets the endpoint IP (it's the SYN destination)
           VIA = the endpoint IP only appears as an encapsulation layer
                 (neither the inner client nor the inner server)
    """
    agg = {}
    for s in prof["streams"].values():
        if not (s.ips_seen & endpoint_ips):
            continue
        oc = s.outcome()
        if s.client_ip in endpoint_ips:
            role, peer = "OUT", s.server_ip
            fqdn = s.sni or s.host
            if not fqdn and s.server_ip:
                names = prof["ip_fqdn"].get(s.server_ip)
                fqdn = sorted(names)[0] if names else None
        elif s.server_ip in endpoint_ips:
            role, peer, fqdn = "IN", s.client_ip, None
        else:
            role, peer, fqdn = "VIA", s.server_ip, (s.sni or s.host)
        key = (role, peer or "?", s.server_port or "?", oc, fqdn or "")
        agg[key] = agg.get(key, 0) + 1
    return agg


def _format_flows(agg, indent="      ", limit=None):
    """Render aggregated source-IP flows as readable lines."""
    arrow = {"OUT": "→", "IN": "←", "VIA": "↔"}
    items = sorted(agg.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2]))
    shown = items if limit is None else items[:limit]
    lines = []
    for (role, peer, port, oc, fqdn), count in shown:
        dest = f"{peer}:{port}"
        name = f"  ({fqdn})" if fqdn else ""
        times = f"  ×{count}" if count > 1 else ""
        lines.append(f"{indent}{role:<3} {arrow[role]} {dest:<22} {oc}{name}{times}")
    if limit is not None and len(items) > limit:
        lines.append(f"{indent}… +{len(items) - limit} more flow group(s) — run with --debug")
    return lines


def _inbound_failures(connectors, endpoint_ips):
    """
    Connector flows where something is trying to REACH an endpoint source IP
    (the endpoint IP is the SYN destination) and the connection FAILS — SYN with
    no SYN-ACK, RST, or a half-open connect with no data. Aggregated by
    (connector, source, endpoint IP, port, outcome) -> count of attempts.
    """
    agg = {}
    for prof in connectors:
        name = os.path.basename(prof.get("path", "")) or "connector"
        for s in prof["streams"].values():
            if s.server_ip in endpoint_ips and s.outcome() in (
                    "no_response", "reset", "half_open"):
                key = (name, s.client_ip or "?", s.server_ip, s.server_port,
                       s.outcome())
                agg[key] = agg.get(key, 0) + 1
    return agg


def report(good, bad, connectors=None, src_override=None, debug=False):
    connectors = connectors or []
    _print_ignore_banner()

    good_dests = build_destinations(good)
    bad_dests = build_destinations(bad)
    bad_by_fqdn, bad_by_ip = _index_dests(bad_dests)

    # The endpoint source IP(s), pulled from the BAD tunnel packets: whoever
    # issues the DNS queries / originates the connections. Overridable with --src.
    if src_override:
        endpoint_ips = set(src_override)
    else:
        endpoint_ips = set(bad.get("dns_query_src") or {}) | set(bad.get("client_ips") or {})

    if debug:
        _print_debug(good, bad, connectors, endpoint_ips)

    # Analyze each connector pcap for that IP as SOURCE or DESTINATION, and run the
    # analysis on just those flows. Connectors that don't contain the IP at all
    # contribute nothing (and are flagged — likely NAT'd or the wrong capture).
    per_connector = []   # (profile, scoped_dests, matched_flow_count)
    for prof in connectors:
        if endpoint_ips:
            dests = build_destinations(prof, only_involving_ips=endpoint_ips)
            matched = sum(1 for s in prof["streams"].values()
                          if s.ips_seen & endpoint_ips)
        else:
            dests = build_destinations(prof)
            matched = len(prof["streams"])
        per_connector.append((prof, dests, matched))
    connector_usable = any(m > 0 for _, _, m in per_connector)
    conn_dests = _merge_dests([d for _, d, _ in per_connector])
    conn_by_fqdn, conn_by_ip = _index_dests(conn_dests)
    conn_dns_failed = set()
    for prof in connectors:
        conn_dns_failed |= prof.get("dns_failed", set())

    # Required = destinations the app used successfully in the office, MINUS the
    # ignored vendors (Microsoft / Google).
    required = {}
    ignored = []
    for k, d in good_dests.items():
        if d["outcome"] != "ok":
            continue
        vendor = ignored_vendor(d["fqdn"])
        if vendor:
            ignored.append((d, vendor))
        else:
            required[k] = d

    reachable, missing = [], []
    for (_, port), d in required.items():
        fqdn = d["fqdn"]
        bad_d = _lookup_dest(d, bad_by_fqdn, bad_by_ip)

        if bad_d and bad_d["outcome"] == "ok":
            reachable.append(d)
            continue

        # Work out WHY it's failing for the client (endpoint side).
        if fqdn and fqdn not in bad["dns_resolved"]:
            if fqdn in bad["dns_failed"]:
                reason = "DNS lookup FAILED via Network Presence (NXDOMAIN / no answer)"
            elif fqdn in bad["dns_queried"]:
                reason = "DNS queried but never resolved via Network Presence"
            else:
                reason = "never reached — DNS not even attempted (app gave up)"
        elif bad_d is None:
            reason = "resolved, but the app never connected (no SYN to it)"
        elif bad_d["outcome"] == "no_response":
            reason = "TCP SYN sent but got NO SYN-ACK (not covered by segment)"
        elif bad_d["outcome"] == "reset":
            reason = "connection RESET before data (not covered by segment)"
        elif bad_d["outcome"] == "half_open":
            reason = "connected but server sent no data (likely blocked)"
        else:
            reason = "did not complete in the bad capture"

        trace = None
        if connectors and connector_usable:
            trace = _connector_trace(d, conn_dns_failed, conn_by_fqdn, conn_by_ip)
        missing.append((d, reason, trace))

    show_conn = bool(connectors) and connector_usable
    inbound = _inbound_failures(connectors, endpoint_ips) if (connectors and endpoint_ips) else {}
    _print_summary(good, bad, per_connector, good_dests, bad_dests, required, ignored)
    _print_correlation(endpoint_ips, per_connector, bool(connectors),
                       connector_usable, bool(src_override))
    _print_missing(missing, show_conn)
    _print_reachable(reachable)
    _print_unnamed(missing)
    _print_inbound(inbound)


def _fmt_dest(d):
    name = d["fqdn"] or "(no DNS name)"
    ips = ", ".join(sorted(d["ips"])[:4])
    more = f" +{len(d['ips']) - 4}" if len(d["ips"]) > 4 else ""
    return name, d["port"], f"{ips}{more}"


def _print_debug(good, bad, connectors, endpoint_ips):
    """Dump the IP inventory the script actually parsed from each capture, so a
    source-IP that 'should be there' but isn't matching can be diagnosed."""
    print(f"\n{'=' * 60}")
    print("🐞  DEBUG — IP inventory per capture")
    print(f"{'=' * 60}")
    eps = ", ".join(sorted(endpoint_ips)) if endpoint_ips else "(none detected)"
    print(f"  Active endpoint source IP(s): {eps}")

    rows = [("GOOD endpoint", good), ("BAD endpoint", bad)]
    rows += [(f"CONNECTOR {os.path.basename(p.get('path', '')) or i}", p)
             for i, p in enumerate(connectors, 1)]
    for label, prof in rows:
        sc = prof.get("all_src_counts", Counter())
        dc = prof.get("all_dst_counts", Counter())
        print(f"\n  [{label}]  packets={prof['total_packets']}  "
              f"tcp_streams={len(prof['streams'])}")
        tun = prof.get("tunneled_rows", 0)
        if tun:
            print(f"    ⚠️  {tun} packet(s) had multiple IPs in one field "
                  "(tunnelled/encapsulated):")
            for ex in prof.get("tunneled_examples", []):
                print(f"          {ex}")
        print("    top sources:      "
              + (", ".join(f"{ip}({n})" for ip, n in sc.most_common(8)) or "—"))
        print("    top destinations: "
              + (", ".join(f"{ip}({n})" for ip, n in dc.most_common(8)) or "—"))
        for ip in sorted(endpoint_ips):
            as_src = sc.get(ip, 0)
            as_dst = dc.get(ip, 0)
            ntcp = sum(1 for s in prof["streams"].values() if ip in s.ips_seen)
            flag = "✓ present" if (as_src or as_dst) else "✗ NOT in this capture"
            print(f"    → {ip}: as-src={as_src} as-dst={as_dst} "
                  f"in {ntcp} TCP stream(s)   {flag}")
            if as_src and not ntcp:
                print("        (seen in packets but in NO TCP stream — likely "
                      "UDP/QUIC, which TCP outcome analysis can't classify)")
        flows = _source_ip_flows(prof, endpoint_ips)
        if flows:
            print(f"    flows involving the source IP ({sum(flows.values())} "
                  f"stream(s), {len(flows)} group(s)):")
            for ln in _format_flows(flows, indent="      ", limit=60):
                print(ln)


def _print_ignore_banner():
    vendors = " / ".join(IGNORED_VENDORS)
    print(f"\nℹ️  Ignoring {vendors} traffic for now (telemetry / CDN noise the app")
    print("    doesn't depend on). Those destinations are excluded from this report.")
    print("    Matched by FQDN suffix — edit IGNORED_VENDORS in the script to change.")


def _print_summary(good, bad, per_connector, good_dests, bad_dests, required, ignored):
    print(f"\n{'=' * 60}")
    print("📊  CAPTURE SUMMARY")
    print(f"{'=' * 60}")
    rows = [("GOOD endpoint (office, ZPA off)", good, good_dests, None),
            ("BAD  endpoint (ZPA on)", bad, bad_dests, None)]
    for i, (prof, dests, matched) in enumerate(per_connector, 1):
        name = os.path.basename(prof.get("path", "")) or f"capture {i}"
        suffix = f" #{i} ({name})" if len(per_connector) > 1 else f" ({name})"
        rows.append((f"App Connector{suffix}", prof, dests, matched))
    for label, prof, dests, matched in rows:
        ok = sum(1 for d in dests.values() if d["outcome"] == "ok")
        print(f"\n  {label}")
        print(f"    packets ............. {prof['total_packets']}")
        if matched is not None:
            print(f"    flows w/ source IP .. {matched}")
        print(f"    TCP destinations .... {len(dests)}  ({ok} reached OK)")
        print(f"    FQDNs resolved ...... {len(prof['dns_resolved'])}")
        print(f"    DNS lookups failed .. {len(prof['dns_failed'])}")
    print(f"\n  → App uses {len(required)} working destination(s) in the office "
          "(after exclusions).")
    if ignored:
        by_vendor = Counter(v for _, v in ignored)
        breakdown = ", ".join(f"{v}: {n}" for v, n in by_vendor.items())
        print(f"  → Excluded {len(ignored)} ignored destination(s)  ({breakdown}).")


def _print_correlation(endpoint_ips, per_connector, has_connector,
                       connector_usable, overridden):
    """Show the endpoint source IP and how each connector capture matched it."""
    if endpoint_ips:
        shown = ", ".join(sorted(endpoint_ips)[:6])
        origin = "from --src" if overridden else "from BAD tunnel packets"
        print(f"\n  Endpoint source IP(s) ({origin}): {shown}")
    else:
        print("\n  ⚠️  No endpoint source IP found in the BAD capture "
              "(use --src IP to set it).")
    if not has_connector:
        return
    print("  Connector pcaps analyzed for that IP as source/destination:")
    for prof, dests, matched in per_connector:
        name = os.path.basename(prof.get("path", "")) or "connector"
        if matched > 0:
            print(f"    • {name}: {matched} flow(s) involving the source IP "
                  f"→ {len(dests)} destination(s) analyzed.")
            flows = _source_ip_flows(prof, endpoint_ips)
            for ln in _format_flows(flows, indent="        ", limit=12):
                print(ln)
        else:
            print(f"    • {name}: source IP NOT seen here — nothing to analyze "
                  "(App Connector may NAT the client, or wrong capture).")
    if not connector_usable:
        print("\n  ⚠️  The endpoint source IP doesn't appear in ANY connector "
              "capture, so connector\n"
              "      break-point tracing is skipped. Either the connector "
              "source-NATs the client\n"
              "      (capture where the tunnel source is visible), or pass the "
              "right IP with --src.")


def _print_missing(missing, has_connector):
    print(f"\n{'=' * 60}")
    print(f"🚫  MISSING FROM NETWORK PRESENCE  —  add these ({len(missing)})")
    print(f"{'=' * 60}")
    if not missing:
        print("\n  Nothing missing — every destination the app used in the office")
        print("  was also reachable with Network Presence on. Coverage looks complete. ✅")
        return
    # FQDN-named first (these are what you add to the App Segment).
    named = [m for m in missing if m[0]["fqdn"]]
    named.sort(key=lambda m: m[0]["fqdn"])
    for d, reason, trace in named:
        name, port, ips = _fmt_dest(d)
        print(f"\n  • {name}:{port}")
        print(f"      real IP(s): {ips}")
        print(f"      client side: {reason}")
        if has_connector:
            print(f"      connector:   {trace or 'n/a'}")
    # Wildcard suggestions when several FQDNs share a parent domain.
    parents = defaultdict(set)
    for d, _, _ in named:
        parents[_parent_domain(d["fqdn"])].add(d["fqdn"])
    wildcards = {p: names for p, names in parents.items() if len(names) > 1}
    if wildcards:
        print(f"\n  💡 Wildcard segment candidates (several names share a parent):")
        for parent, names in sorted(wildcards.items()):
            print(f"      *.{parent}   covers {len(names)} of the above")


def _print_reachable(reachable):
    if not reachable:
        return
    print(f"\n{'=' * 60}")
    print(f"🟢  REACHABLE VIA NETWORK PRESENCE ({len(reachable)})")
    print(f"{'=' * 60}")
    reachable.sort(key=lambda d: (d["fqdn"] or ""))
    for d in reachable:
        name, port, _ = _fmt_dest(d)
        print(f"  • {name}:{port}")


_INBOUND_LABEL = {
    "no_response": "SYN, no SYN-ACK",
    "reset": "RST (reset)",
    "half_open": "SYN-ACK but no data",
}


def _print_inbound(agg):
    """Report failing connector flows aimed AT the endpoint source IP."""
    if not agg:
        return
    print(f"\n{'=' * 60}")
    print(f"🔻  INBOUND FAILURES TOWARD THE SOURCE IP ({len(agg)})")
    print(f"{'=' * 60}")
    print("  Something in the connector capture(s) tried to REACH the endpoint")
    print("  source IP and the connection failed:")
    for (name, src, dst, port, oc), count in sorted(agg.items()):
        times = f"  (×{count})" if count > 1 else ""
        print(f"  • {src} → {dst}:{port}   {_INBOUND_LABEL[oc]}{times}   [{name}]")


def _print_unnamed(missing):
    unnamed = [m[0] for m in missing if not m[0]["fqdn"]]
    if not unnamed:
        return
    print(f"\n{'=' * 60}")
    print(f"🔢  MISSING IP-ONLY DESTINATIONS — no DNS name seen ({len(unnamed)})")
    print(f"{'=' * 60}")
    print("  These had no FQDN in the capture; add them as IP-based segments,")
    print("  or capture DNS alongside to recover the hostname.")
    for d in unnamed:
        ips = ", ".join(sorted(d["ips"]))
        print(f"  • {ips}:{d['port']}")


def _parse_argv(argv):
    """Parse --src IP / --src=IP (repeatable, comma-OK) and --debug.
    Returns (src_list, debug_bool, positionals)."""
    src, debug, positional, i = [], False, [], 0
    while i < len(argv):
        a = argv[i]
        if a == "--src" and i + 1 < len(argv):
            src += [x for x in argv[i + 1].split(",") if x]
            i += 2
            continue
        if a.startswith("--src="):
            src += [x for x in a.split("=", 1)[1].split(",") if x]
            i += 1
            continue
        if a == "--debug":
            debug = True
            i += 1
            continue
        if not a.startswith("-"):
            positional.append(a)
        i += 1
    return src, debug, positional


def main():
    print("🔍 PCAP Compare — ZPA Network Presence coverage finder")
    print("=" * 60)

    tshark = find_tshark()
    if not tshark:
        print(
            "\n❌ tshark not found. Install Wireshark, then re-run.\n"
            "   macOS:    brew install --cask wireshark\n"
            "   Windows:  install from https://www.wireshark.org/download.html\n"
            "             (tshark.exe lands in C:\\Program Files\\Wireshark\\)"
        )
        sys.exit(1)

    conn_files = []
    src_override, debug, args = _parse_argv(sys.argv[1:])
    if len(args) >= 2:
        # CLI mode: pcap_compare.py [--src IP] GOOD BAD [CONNECTOR ...]
        good_file, bad_file = args[0], args[1]
        conn_files = args[2:]
        checks = [("GOOD", good_file), ("BAD", bad_file)]
        checks += [("CONNECTOR", f) for f in conn_files]
        for label, f in checks:
            if not os.path.isfile(f):
                print(f"❌ {label} capture not found: {f}")
                sys.exit(1)
    elif args:
        print("Usage: pcap_compare.py [--src IP] [GOOD BAD [CONNECTOR ...]]"
              "   (no args = file pickers)")
        sys.exit(1)
    else:
        print("\n📂 Select the GOOD endpoint capture — office, ZPA/VPN OFF…")
        good_file = select_pcap_file("Select GOOD endpoint pcap (ZPA off, working)")
        if not good_file:
            print("❌ No good capture selected. Exiting.")
            return

        print("📂 Select the BAD endpoint capture — ZPA / Network Presence ON…")
        bad_file = select_pcap_file("Select BAD endpoint pcap (ZPA on, failing)")
        if not bad_file:
            print("❌ No bad capture selected. Exiting.")
            return

        print("📂 (Optional) Select App Connector capture(s) — multi-select OK, cancel to skip…")
        conn_files = select_pcap_files(
            "Select App Connector pcap(s) (optional — multi-select, cancel to skip)")

    print(f"\n  Good endpoint: {good_file}")
    print(f"  Bad endpoint:  {bad_file}")
    for i, f in enumerate(conn_files, 1):
        print(f"  App Connector {i}: {f}")
    print("\n⏳ Analyzing with tshark…")

    try:
        good = parse_capture(tshark, good_file)
        bad = parse_capture(tshark, bad_file)
        connectors = [parse_capture(tshark, f) for f in conn_files]
    except RuntimeError as e:
        print(f"\n❌ {e}")
        sys.exit(1)

    report(good, bad, connectors, src_override=src_override, debug=debug)
    print()


if __name__ == "__main__":
    main()
