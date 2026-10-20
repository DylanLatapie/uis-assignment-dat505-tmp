# CUPS Printer Discovery Exploitation and Attack Detection Using Scapy

**Course:** DAT505-1 26H · **Due:** Nov 16 by 11:59pm · **Submitting:** a file upload (PDF) + this GitHub repository

> Individual assignment. Everything runs in an **isolated** Docker/VM lab. No
> public, university, or third-party system is ever targeted.

---

## Scenario

The Common Unix Printing System (CUPS) is widely used to manage printers in
Linux environments. In 2024, several vulnerabilities were discovered in CUPS,
including **CVE-2024-47176**, **CVE-2024-47076**, and **CVE-2024-47175**,
allowing attackers to manipulate printer-discovery mechanisms and potentially
compromise vulnerable systems.

In this assignment, I investigate these vulnerabilities by developing
Scapy-based **attack** and **detection** tools against an existing vulnerable
CUPS environment.

**Vulnerable environment:**
<https://github.com/vulhub/vulhub/tree/master/cups-browsed/CVE-2024-47177>

> Note: the Vulhub directory retains the rejected CVE-2024-47177 identifier.

---

## Task 1: Virtual Environment Setup

Set up an isolated laboratory containing:

- **Attacker:** Kali Linux or Ubuntu with Python, Scapy, and Wireshark/tcpdump.
- **Victim:** vulnerable CUPS Docker container provided by Vulhub.
- **Virtual Printer:** a software-based IPP server, such as OpenPrinting's `ippserver`.

No physical printer is required. Existing software may be used to simulate a
network printer. Document the network configuration and capture normal
printer-discovery traffic.

## Task 2: CUPS Attack Tool Using Scapy

Develop `cups_attack.py` to investigate insecure printer discovery. The tool must:

- Construct and send custom CUPS printer-discovery packets using Scapy.
- Advertise an attacker-controlled virtual printer to the vulnerable CUPS service.
- Manipulate printer addresses, ports, and discovery message fields.
- Demonstrate whether the victim initiates communication with the advertised printer.
- Support command-line arguments, logging, and PCAP export.

Full remote code execution is not required; the focus is on demonstrating the
insecure printer-discovery mechanism.

## Task 3: CUPS Attack Detection Tool

Develop `cups_detector.py` using Scapy to identify suspicious CUPS network
activity. Implement detection for:

- Unauthorized printer advertisements.
- Suspicious IPP connections.
- Repeated or abnormal printer-discovery messages.
- Malformed or unexpected protocol fields.

The tool must support **live monitoring or offline PCAP analysis**, generate
security alerts, and export results to **CSV or JSON**.

## Task 4: Attack Simulation and Analysis

Perform the following experiments:

- **Normal traffic:** capture legitimate communication between CUPS and the virtual printer.
- **Unauthorized discovery:** use the attack tool to advertise an attacker-controlled printer.
- **Packet manipulation:** test at least three variations of crafted discovery messages.
- **Detection:** analyse normal and attack traffic using the detection tool.

Provide PCAP files, screenshots, logs, and an explanation of the observed
behaviour. Evaluate successful detections, false positives, and missed attacks.

## Task 5: Defence and Mitigation

Investigate security measures such as:

- Restricting UDP port 631.
- Disabling unnecessary `cups-browsed` functionality.
- Allowlisting authorized printer addresses.
- Applying security patches and network segmentation.

Implement at least one mitigation and compare the results before and after
applying it.

---

## Submission Requirements

This is an individual assignment. Submit a GitHub repository containing:

- `cups_attack.py`: Scapy-based attack tool.
- `cups_detector.py`: Scapy-based detection tool.
- `README.md` and `requirements.txt`.
- `pcap_files/`: captured network traffic.
- `evidence/`: screenshots and logs.

Submit a PDF report describing the environment, tool implementations,
experiments, results, mitigations, and ethical considerations.

## Important Rules

- Use only isolated Docker containers or virtual machines.
- No physical printer is required.
- Students must develop their own Scapy-based attack and detection logic.
- Existing vulnerable environments and software-based printer simulators may be used.
- Never target public, university, or third-party systems without authorization.

---

## Repository

| Path | Description |
|------|-------------|
| `cups_attack.py` | Scapy attack tool (Task 2) |
| `cups_detector.py` | Scapy detection tool (Task 3) |
| `requirements.txt` | Python dependencies (`scapy`) |
| `pcap_files/` | captured traffic: `01-normal`, `02-attack`, `03-malformed`, `04-mitigated` (+ attacker-side send) |
| `evidence/screenshots/` | screenshots (lab, attack, detection, mitigation) |
| `evidence/logs/` | detector alert exports (CSV/JSON) per scenario |
| `report/` | LaTeX source of the PDF report (`report.pdf`) |

### Quick start

```bash
# victim container (isolated lab)
git clone https://github.com/vulhub/vulhub.git
cd vulhub/cups-browsed/CVE-2024-47177 && docker compose up -d

# tools
pip install -r requirements.txt        # or: sudo apt install python3-scapy

sudo python3 cups_attack.py --help
sudo python3 cups_detector.py --help
```

See `report/report.pdf` for the full write-up.
