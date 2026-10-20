#!/usr/bin/env python3
"""
cups_detector.py: DAT505 Assignment 2 (Task 3).

Scapy-based detector for suspicious CUPS / cups-browsed network activity.
Works on a live interface or on an offline PCAP, raises security alerts, and
exports them to CSV or JSON.

Detections (per the assignment):
  - unauthorized_advertisement : a CUPS browse/discovery packet (UDP/631)
        advertising a printer whose host is not on the allowlist.
  - repeated_advertisement     : the same source floods browse packets
        (rate above a threshold inside a time window).
  - malformed_browse           : a UDP/631 payload that does not parse as a
        well-formed legacy CUPS browse advertisement, or carries out-of-range
        / suspicious fields (bad port, control chars, oversized URI).
  - suspicious_ipp_connection  : the monitored CUPS host opens an OUTBOUND TCP
        connection to an advertised address:port (the printer it was told to
        talk to), i.e. the host acted on an unsolicited advertisement.

Scope: isolated lab traffic only.

Examples:
    # offline, against a capture, JSON out
    python3 cups_detector.py --pcap pcap_files/02-attack.pcap \
        --cups-host 172.18.0.2 --allow 172.18.0.1 --json alerts.json

    # live on the lab bridge, CSV out
    sudo python3 cups_detector.py --iface br-ec2a7d724d82 \
        --cups-host 172.18.0.2 --allow 172.18.0.1 --csv alerts.csv
"""
import argparse
import csv
import json
import logging
import re
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict

try:
    from scapy.all import IP, TCP, UDP, Raw, rdpcap, sniff
except ImportError:
    sys.stderr.write("scapy is required: pip install -r requirements.txt\n")
    sys.exit(1)

CUPS_PORT = 631
log = logging.getLogger("cups_detector")

# Legacy browse datagram: "<type> <state> <uri> [\"loc\" \"info\" \"model\"]".
_URI_RE = re.compile(r"[a-z]+://([^/\s:]+)(?::(\d+))?", re.IGNORECASE)
_BROWSE_RE = re.compile(r"^\s*[0-9a-fA-Fx]+\s+[0-9a-fA-Fx]+\s+\S+://\S+")
_MAX_URI_LEN = 1024


@dataclass
class Alert:
    ts: float
    kind: str
    severity: str
    src: str
    dst: str
    detail: str

    def row(self):
        d = asdict(self)
        d["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))
        return d


@dataclass
class Detector:
    cups_host: str | None = None
    allow: set[str] = field(default_factory=set)
    rate_window: float = 10.0        # seconds
    rate_threshold: int = 5          # browse packets per source per window
    alerts: list[Alert] = field(default_factory=list)
    _seen: dict[str, deque] = field(default_factory=lambda: defaultdict(deque))

    # -- helpers ----------------------------------------------------------
    def _add(self, ts, kind, severity, src, dst, detail):
        a = Alert(ts, kind, severity, src, dst, detail)
        self.alerts.append(a)
        log.warning("[%s] %s %s->%s : %s", severity.upper(), kind, src, dst, detail)
        return a

    @staticmethod
    def _parse_browse(payload: bytes):
        """Return (uri, host, port, ok) for a legacy browse datagram.
        ok=False means the payload is malformed."""
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError:
            return (None, None, None, False)
        if not _BROWSE_RE.match(text):
            return (None, None, None, False)
        parts = text.split()
        uri = parts[2] if len(parts) >= 3 else ""
        m = _URI_RE.match(uri)
        if not m:
            return (uri, None, None, False)
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else CUPS_PORT
        return (uri, host, port, True)

    # -- per-packet handling ---------------------------------------------
    def handle(self, pkt):
        if IP not in pkt:
            return
        ts = float(pkt.time)
        ip = pkt[IP]

        # ---- UDP/631 : browse / discovery advertisements ----
        if UDP in pkt and (pkt[UDP].dport == CUPS_PORT or pkt[UDP].sport == CUPS_PORT):
            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            uri, host, port, ok = self._parse_browse(payload)

            if not ok:
                self._add(ts, "malformed_browse", "medium", ip.src, ip.dst,
                          f"unparseable browse datagram ({len(payload)} bytes): "
                          f"{payload[:60]!r}")
            else:
                # field sanity
                if len(uri) > _MAX_URI_LEN:
                    self._add(ts, "malformed_browse", "medium", ip.src, ip.dst,
                              f"oversized URI ({len(uri)} bytes)")
                if port is not None and not (0 < port < 65536):
                    self._add(ts, "malformed_browse", "medium", ip.src, ip.dst,
                              f"invalid port in URI: {port}")
                # Strict model: any non-allowlisted advertised host is flagged
                # (empty allowlist => every advertisement is unauthorized).
                if host and host not in self.allow and ip.src not in self.allow:
                    self._add(ts, "unauthorized_advertisement", "high", ip.src, ip.dst,
                              f"advertises printer at {host}:{port} (uri={uri})")

            # rate tracking (any browse packet, well-formed or not)
            dq = self._seen[ip.src]
            dq.append(ts)
            while dq and ts - dq[0] > self.rate_window:
                dq.popleft()
            if len(dq) == self.rate_threshold + 1:  # fire once when crossing
                self._add(ts, "repeated_advertisement", "high", ip.src, ip.dst,
                          f"{len(dq)} browse packets in {self.rate_window:.0f}s window")

        # ---- TCP/631 : IPP connections ----
        elif TCP in pkt:
            flags = pkt[TCP].flags
            syn, ack = (flags & 0x02), (flags & 0x10)
            # Fresh outbound SYN from the CUPS host to any non-allowlisted target
            # (the advertised printer's port, not 631) = it acted on an ad.
            if syn and not ack and self.cups_host and ip.src == self.cups_host:
                if ip.dst not in self.allow:
                    self._add(ts, "suspicious_ipp_connection", "high", ip.src, ip.dst,
                              f"CUPS host opened outbound connection to non-allowlisted "
                              f"{ip.dst}:{pkt[TCP].dport} (acted on an advertisement)")

    # -- drivers ----------------------------------------------------------
    def run_pcap(self, path):
        log.info("Reading %s", path)
        for pkt in rdpcap(path):
            self.handle(pkt)

    def run_live(self, iface):
        log.info("Live capture on %s (Ctrl-C to stop)", iface)
        bpf = f"port {CUPS_PORT}"
        sniff(iface=iface, filter=bpf, prn=self.handle, store=False)


def export_csv(alerts, path):
    fields = ["time", "ts", "kind", "severity", "src", "dst", "detail"]
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for a in alerts:
            w.writerow(a.row())


def export_json(alerts, path):
    with open(path, "w") as fh:
        json.dump([a.row() for a in alerts], fh, indent=2)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Scapy CUPS/cups-browsed suspicious-activity detector.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="analyse an offline capture")
    src.add_argument("--iface", help="live capture interface (needs root)")
    p.add_argument("--cups-host", help="IP of the monitored CUPS host (victim)")
    p.add_argument("--allow", action="append", default=[],
                   help="allowlisted printer/host IP (repeatable)")
    p.add_argument("--rate-window", type=float, default=10.0,
                   help="seconds for the repeat-rate window (default 10)")
    p.add_argument("--rate-threshold", type=int, default=5,
                   help="browse packets per source per window before alert (default 5)")
    p.add_argument("--csv", help="write alerts to this CSV file")
    p.add_argument("--json", help="write alerts to this JSON file")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s")

    det = Detector(
        cups_host=args.cups_host,
        allow=set(args.allow),
        rate_window=args.rate_window,
        rate_threshold=args.rate_threshold,
    )
    try:
        if args.pcap:
            det.run_pcap(args.pcap)
        else:
            det.run_live(args.iface)
    except FileNotFoundError:
        log.error("PCAP not found: %s", args.pcap)
        return 1
    except PermissionError:
        log.error("Live capture needs root (try sudo).")
        return 1
    except KeyboardInterrupt:
        log.info("Stopped.")

    log.info("Total alerts: %d", len(det.alerts))
    if args.csv:
        export_csv(det.alerts, args.csv)
        log.info("Wrote %s", args.csv)
    if args.json:
        export_json(det.alerts, args.json)
        log.info("Wrote %s", args.json)
    if not det.alerts:
        log.info("No suspicious activity detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
