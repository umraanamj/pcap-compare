#!/usr/bin/env python3
"""
PCAP Compare — Zscaler ZPA "Network Presence" coverage finder.

The problem this solves
-----------------------
ZPA Network Presence only lets an app reach the exact IPs / FQDNs you've listed
in its Application Segment. App owners rarely know the full list, so connections
to anything missing just fail. This script finds what's missing.

  GOOD capture = taken in the office with ZPA / VPN OFF (full connectivity).
                 This is the GROUND TRUTH of every destination the app uses.
  BAD  capture = taken with ZPA / Network Presence ON. The app can only reach
                 what's already in the segment, so the gaps show up as failures.

The script enumerates every destination the app talks to in the GOOD capture,
then reports which ones FAIL or never appear in the BAD capture — i.e. the
IPs/FQDNs you need to add to the Application Segment.

Launch flow (unchanged): file picker for the GOOD capture, then the BAD capture.
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

Requires Wireshark's `tshark` on PATH (or in the macOS Wireshark.app bundle).
  macOS:  brew install --cask wireshark
"""

import os
import shutil
import subprocess
import sys
from collections import defaultdict

import tkinter as tk
from tkinter import filedialog

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


def find_tshark():
    """Locate tshark on PATH or in the standard macOS Wireshark.app location."""
    path = shutil.which("tshark")
    if path:
        return path
    mac_default = "/Applications/Wireshark.app/Contents/MacOS/tshark"
    if os.path.exists(mac_default):
        return mac_default
    return None


def select_pcap_file(title):
    """Open a native file-picker dialog for a pcap / pcapng file."""
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    file_path = filedialog.askopenfilename(
        title=title,
        filetypes=[
            ("Capture files", "*.pcap *.pcapng *.cap"),
            ("All files", "*.*"),
        ],
    )
    root.destroy()
    return file_path


class StreamStat:
    """Per-TCP-stream rollup used to decide if a connection succeeded."""

    def __init__(self):
        self.server_ip = None
        self.server_port = None
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
    total_packets = 0

    for line in proc.stdout.splitlines():
        if not line:
            continue
        total_packets += 1
        cols = line.split("\t")
        if len(cols) < len(TSHARK_FIELDS):
            cols += [""] * (len(TSHARK_FIELDS) - len(cols))

        ip_src = cols[2]
        ip_dst = cols[3]
        dstport = cols[4]
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

        # Identify the server from the SYN (syn & !ack -> dst is the server).
        if syn and not ack:
            s.syn = True
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

    return {
        "path": path,
        "total_packets": total_packets,
        "streams": dict(streams),
        "dns_answers": dict(dns_answers),
        "dns_resolved": dns_resolved,
        "dns_failed": dns_failed,
        "dns_queried": dns_queried,
        "ip_fqdn": dict(ip_fqdn),
    }


def build_destinations(profile):
    """
    Collapse streams into destinations keyed by (fqdn, port) when an FQDN is
    known, else (ip, port). Returns {key: {fqdn, ips, port, outcome, n}}.
    """
    rank = {"ok": 3, "half_open": 2, "reset": 1, "no_response": 0, "unknown": 0}
    dests = {}
    for s in profile["streams"].values():
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


def report(good, bad):
    good_dests = build_destinations(good)
    bad_dests = build_destinations(bad)

    # Index BAD destinations by fqdn:port and ip:port for lookups.
    bad_by_fqdn = {}
    bad_by_ip = {}
    for (_, port), d in bad_dests.items():
        if d["fqdn"]:
            bad_by_fqdn[(d["fqdn"], port)] = d
        for ip in d["ips"]:
            bad_by_ip[(ip, port)] = d

    # Required = destinations the app actually used successfully in the office.
    required = {k: d for k, d in good_dests.items() if d["outcome"] == "ok"}

    reachable, missing = [], []
    for (_, port), d in required.items():
        fqdn = d["fqdn"]
        bad_d = None
        if fqdn:
            bad_d = bad_by_fqdn.get((fqdn, port))
        if bad_d is None:
            for ip in d["ips"]:
                if (ip, port) in bad_by_ip:
                    bad_d = bad_by_ip[(ip, port)]
                    break

        if bad_d and bad_d["outcome"] == "ok":
            reachable.append(d)
            continue

        # Work out WHY it's failing in the bad capture.
        if fqdn and fqdn not in bad["dns_resolved"]:
            if fqdn in bad["dns_failed"]:
                reason = "DNS lookup FAILED in ZPA (NXDOMAIN / no answer)"
            elif fqdn in bad["dns_queried"]:
                reason = "DNS queried but never resolved through ZPA"
            else:
                reason = "never reached — DNS not even attempted (app gave up)"
        elif bad_d is None:
            reason = "resolved, but the app never connected (no SYN to it)"
        elif bad_d["outcome"] == "no_response":
            reason = "TCP SYN sent but got NO SYN-ACK (blocked by segment)"
        elif bad_d["outcome"] == "reset":
            reason = "connection RESET before data (blocked by segment)"
        elif bad_d["outcome"] == "half_open":
            reason = "connected but server sent no data (likely blocked)"
        else:
            reason = "did not complete in the bad capture"
        missing.append((d, reason))

    _print_summary(good, bad, good_dests, bad_dests, required)
    _print_missing(missing)
    _print_reachable(reachable)
    _print_unnamed(missing)


def _fmt_dest(d):
    name = d["fqdn"] or "(no DNS name)"
    ips = ", ".join(sorted(d["ips"])[:4])
    more = f" +{len(d['ips']) - 4}" if len(d["ips"]) > 4 else ""
    return name, d["port"], f"{ips}{more}"


def _print_summary(good, bad, good_dests, bad_dests, required):
    print(f"\n{'=' * 60}")
    print("📊  CAPTURE SUMMARY")
    print(f"{'=' * 60}")
    for label, prof, dests in (("GOOD (office, ZPA off)", good, good_dests),
                               ("BAD  (ZPA on)", bad, bad_dests)):
        ok = sum(1 for d in dests.values() if d["outcome"] == "ok")
        print(f"\n  {label}")
        print(f"    packets ............. {prof['total_packets']}")
        print(f"    TCP destinations .... {len(dests)}  ({ok} reached OK)")
        print(f"    FQDNs resolved ...... {len(prof['dns_resolved'])}")
        print(f"    DNS lookups failed .. {len(prof['dns_failed'])}")
    print(f"\n  → App uses {len(required)} working destination(s) in the office.")


def _print_missing(missing):
    print(f"\n{'=' * 60}")
    print(f"🚫  MISSING FROM NETWORK PRESENCE  —  add these ({len(missing)})")
    print(f"{'=' * 60}")
    if not missing:
        print("\n  Nothing missing — every destination the app used in the office")
        print("  was also reachable with ZPA on. Coverage looks complete. ✅")
        return
    # FQDN-named first (these are what you add to the App Segment).
    named = [(d, r) for d, r in missing if d["fqdn"]]
    named.sort(key=lambda x: x[0]["fqdn"])
    for d, reason in named:
        name, port, ips = _fmt_dest(d)
        print(f"\n  • {name}:{port}")
        print(f"      real IP(s): {ips}")
        print(f"      why it fails: {reason}")
    # Wildcard suggestions when several FQDNs share a parent domain.
    parents = defaultdict(set)
    for d, _ in named:
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
    print(f"🟢  ALREADY REACHABLE THROUGH ZPA ({len(reachable)})")
    print(f"{'=' * 60}")
    reachable.sort(key=lambda d: (d["fqdn"] or ""))
    for d in reachable:
        name, port, _ = _fmt_dest(d)
        print(f"  • {name}:{port}")


def _print_unnamed(missing):
    unnamed = [d for d, _ in missing if not d["fqdn"]]
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


def main():
    print("🔍 PCAP Compare — ZPA Network Presence coverage finder")
    print("=" * 60)

    tshark = find_tshark()
    if not tshark:
        print(
            "\n❌ tshark not found. Install Wireshark, then re-run.\n"
            "   macOS:  brew install --cask wireshark\n"
            "   (tshark ships inside Wireshark.app/Contents/MacOS/)"
        )
        sys.exit(1)

    print("\n📂 Select the GOOD capture — office, ZPA/VPN OFF (full access)…")
    good_file = select_pcap_file("Select GOOD pcap / pcapng (ZPA off, working)")
    if not good_file:
        print("❌ No good capture selected. Exiting.")
        return

    print("📂 Select the BAD capture — ZPA / Network Presence ON (failing)…")
    bad_file = select_pcap_file("Select BAD pcap / pcapng (ZPA on, failing)")
    if not bad_file:
        print("❌ No bad capture selected. Exiting.")
        return

    print(f"\n  Good: {good_file}")
    print(f"  Bad:  {bad_file}")
    print("\n⏳ Analyzing with tshark…")

    try:
        good = parse_capture(tshark, good_file)
        bad = parse_capture(tshark, bad_file)
    except RuntimeError as e:
        print(f"\n❌ {e}")
        sys.exit(1)

    report(good, bad)
    print()


if __name__ == "__main__":
    main()
