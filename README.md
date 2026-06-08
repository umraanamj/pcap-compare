# pcap-compare — ZPA Network Presence coverage finder

A small Python tool that finds the IPs/FQDNs an application needs that are
**missing from its ZPA Application Segment** (Network Presence).

ZPA Network Presence only lets an app reach the exact destinations listed in its
Application Segment. App owners rarely know the full list, so connections to
anything missing just fail. This tool finds the gaps by comparing captures:

| Capture | Taken with | Role |
|---------|-----------|------|
| **GOOD** endpoint | In the office, **ZPA / VPN OFF** (full connectivity) | Ground truth of every destination the app uses |
| **BAD** endpoint  | **ZPA / Network Presence ON** (failing) | Only reaches what's already in the segment |
| **App Connector** *(optional)* | At the **network connector** that brokers the conversation | Pinpoints *where* a failing flow breaks |

It enumerates every destination the app talks to in the GOOD capture, then
reports which ones **fail or never appear** in the BAD capture — i.e. the
IPs/FQDNs you need to add to the Application Segment.

> **Microsoft / Google traffic is ignored for now.** That telemetry/CDN noise
> isn't something we need to ingest, so those destinations are excluded from the
> report (and the script says so at runtime). The match is by FQDN suffix —
> edit the `IGNORED_VENDORS` lists at the top of `pcap_compare.py` to change it.

### Adding the App Connector capture (where does it break?)

ZPA tunnel traffic has two halves: the **endpoint** (Client Connector) and the
**App Connector** (the network connector that brokers the session). The data path
is `Client → ZPA Service Edge → App Connector → app server`. Capture at the App
Connector ([Zscaler: how to PCAP an App Connector](https://help.zscaler.com/zpa/troubleshooting-app-connectors))
and pass it as a third input, and for every failing destination the tool says
which side of the broker the flow died on:

- **never reached the App Connector** → broker didn't route it (Network Presence
  / App Segment doesn't cover the destination).
- **reached the connector, but the server gave no SYN-ACK / reset** → the app is
  unreachable *behind* the connector (firewall / routing / app down).
- **App Connector reached the server fine** → the break is between the client and
  the connector (broker / return path), not the app.

**Source-IP correlation:** the tool pulls the endpoint's source IP from the BAD
tunnel packets (whoever issues the DNS queries / originates the connections),
then analyzes each connector pcap for **that IP as a source *or* destination** and
runs the break-point analysis on just those flows. The script prints, per
connector, how many flows involving that IP it found:

```
Endpoint source IP(s) (from BAD tunnel packets): 10.6.0.2
Connector pcaps analyzed for that IP as source/destination:
  • appconn1.pcap: 14 flow(s) involving the source IP → 9 destination(s) analyzed.
```

If the IP doesn't appear in a connector capture (the App Connector source-NATs
the client, or it's the wrong capture), that connector contributes nothing and is
flagged; if it's absent from **every** connector, break-point tracing is skipped
with a warning. Override the auto-detected IP with `--src IP` (repeatable, or
comma-separated) — e.g. when the connector sees a ZPA-assigned source IP that
differs from the endpoint's local IP.

Both directions are considered. The break-point trace covers the source IP
**reaching app servers**; separately, an **inbound-failures** section reports
flows in the connector capture(s) where something is trying to **reach the source
IP itself and failing** (SYN with no SYN-ACK, RST, or a half-open connect) — e.g.
a broker/health-check dialing back toward the assigned source IP:

```
🔻  INBOUND FAILURES TOWARD THE SOURCE IP (2)
  • 100.64.0.9 → 10.6.0.2:443    SYN, no SYN-ACK   [appconn1.pcap]
  • 100.64.0.9 → 10.6.0.2:8443   RST (reset)       [appconn1.pcap]
```

**Multiple connectors:** ZPA connector groups load-balance, so an app's flows can
be brokered by any connector in the group. You can pass **several** App Connector
captures (multi-select in the dialog, or list them on the command line). They're
merged into one view and the trace answers *"did **any** connector broker this
successfully?"* — the best outcome across all of them wins.

## Usage

```bash
# Interactive: file picker for GOOD, then BAD, then optional App Connector(s)
# (the connector step is multi-select — pick as many as you captured)
python3 pcap_compare.py

# Or pass captures directly (connectors are optional, and you can list several)
python3 pcap_compare.py GOOD.pcap BAD.pcap
python3 pcap_compare.py GOOD.pcap BAD.pcap CONNECTOR.pcap
python3 pcap_compare.py GOOD.pcap BAD.pcap CONN1.pcap CONN2.pcap CONN3.pcap

# Force the endpoint source IP used to scope the connector pcaps
python3 pcap_compare.py --src 10.6.0.2 GOOD.pcap BAD.pcap CONNECTOR.pcap
```

Works with `.pcap` and `.pcapng` (tshark autodetects).

## Requirements

- **Python 3** — standard library only, no `pip install` needed.
  - On **macOS** the file pickers use the native dialog (`osascript`), so
    **tkinter is not required**. On other platforms it uses `tkinter`, falling
    back to a terminal prompt if Tk isn't available. Either way, the
    `GOOD BAD` command-line form sidesteps the dialogs entirely.
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
