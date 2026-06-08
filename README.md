# pcap-compare — ZPA Network Presence coverage finder

A small Python tool that finds the IPs/FQDNs an application needs that are
**missing from its ZPA Application Segment** (Network Presence).

ZPA Network Presence only lets an app reach the exact destinations listed in its
Application Segment. App owners rarely know the full list, so connections to
anything missing just fail. This tool finds the gaps by comparing two captures:

| Capture | Taken with | Role |
|---------|-----------|------|
| **GOOD** | In the office, **ZPA / VPN OFF** (full connectivity) | Ground truth of every destination the app uses |
| **BAD**  | **ZPA / Network Presence ON** (failing) | Only reaches what's already in the segment |

It enumerates every destination the app talks to in the GOOD capture, then
reports which ones **fail or never appear** in the BAD capture — i.e. the
IPs/FQDNs you need to add to the Application Segment.

## Usage

```bash
python3 pcap_compare.py
```

On launch it pops a native file picker for the **GOOD** capture, then the
**BAD** capture. Works with `.pcap` and `.pcapng` (tshark autodetects).

## Requirements

- **Python 3** (standard library only — uses `tkinter` for the file dialogs).
- **Wireshark's `tshark`** on your PATH.
  - macOS: `brew install --cask wireshark` (tshark ships inside
    `Wireshark.app/Contents/MacOS/`, which the script also checks automatically).

## How it works

1. **Builds a destination inventory** from each capture — every TCP destination,
   tagged with its FQDN from DNS queries, TLS SNI, and HTTP Host headers.
2. **Takes GOOD as ground truth** — the destinations the app actually reached
   successfully in the office (got a SYN-ACK *and* the server sent data).
3. **Checks each against BAD** and classifies *why* it fails, distinguishing the
   two failure modes that matter for Network Presence:
   - **DNS never resolves** through ZPA (NXDOMAIN / no answer) → ZPA doesn't know
     the FQDN.
   - **Resolves but the SYN gets no SYN-ACK / RST** → not covered by the segment.
4. **Prints the "add these" list** as `FQDN:port` with the real office IPs, plus
   what's already reachable, IP-only destinations with no DNS name, and wildcard
   suggestions when several missing names share a parent domain (`*.example.com`).

### Why it matches on FQDN, not IP

With ZPA on, DNS resolves through Zscaler and often returns **different or
synthetic IPs**, so the same FQDN has different IPs in the two captures. The tool
joins destinations by **FQDN** (from DNS, SNI, and HTTP Host), which is why it
correctly recognises a destination as "already covered" even when its IP changed.

## Tips & limitations

- **Capture DNS in both pcaps** — don't filter to just the app's IPs. FQDN
  matching depends on seeing the DNS queries/responses. Destinations with no
  visible name fall back to an IP-only list.
- It classifies **TCP** reach/fail outcomes (SYN / SYN-ACK semantics). Pure-UDP
  app traffic isn't outcome-classified.
- A destination only counts as "required" if it **actually succeeded** in the
  GOOD capture, so make sure that capture exercises the full app workflow.
