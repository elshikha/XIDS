# XIDS: Network Traffic Analyzer

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**XIDS (eXperimental Intrusion Detection System)** is a Python-based tool for analyzing PCAP files or live network traffic to detect and report malicious activity. It combines a BERT-based classifier with Snort rule matching, and produces a comprehensive, interactive HTML report using Plotly.

Designed for cybersecurity analysts, incident responders, and network administrators.

---

## Features

- **Hybrid Detection Engine**  
  Detects threats using a combination of deep learning (BERT model) and traditional Snort rule matching. Supports over 24 attack categories.

- **Interactive Visual Reports**  
  Generates an HTML report with:
  - Attack timeline (Plotly line chart)
  - Source-to-destination IP heatmap
  - Network graph of communicating endpoints
  - Top contacted TCP ports
  - Packet size distribution histogram

- **Traffic Filtering Options**  
  - Byte-sequence filtering for PCAP files (e.g. `--filter "GET"`)
  - BPF syntax filtering for live captures (e.g. `--filter "tcp port 80"`)

- **Interface Discovery with Friendly Names**  
  Lists available interfaces with readable names and IP addresses for easier selection.

---

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/xids.git
   cd xids
````

2. **Set Up Environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install torch transformers scapy plotly networkx jinja2
   ```

3. **Install Npcap (Windows Only)**
   Required for packet capture:

   * Download from [npcap.com](https://npcap.com/)
   * Enable:

     * “Support loopback traffic”
     * “WinPcap API-compatible mode”

4. **Add Snort Rules**

   * Create an `r/` folder.
   * Add `.rules` files (e.g., `ddos.rules`) with content like:

     ```
     alert tcp any any -> any 80 (msg:"SQL Injection"; content:"SELECT * FROM"; nocase; sid:1000001;)
     ```

---

## Usage

### Analyze a PCAP File

```bash
python xids.py -f uploads/portscan.pcap -o report.html --filter "GET"
```

* `-f`: Path to the PCAP file
* `-o`: Output HTML report path
* `--filter`: Optional byte sequence (e.g. `GET`); omit to process all packets

### Live Traffic Capture

```bash
python xids.py -o report.html --filter "tcp port 80"
```

* Lists interfaces with names and IPs
* Captures on selected interface until stopped (`Ctrl+C`)
* `--filter`: Optional BPF syntax

**Example Interface List**

```
Available network interfaces:
1. Wi-Fi (Intel(R) Wireless-AC 9560)
   GUID: \Device\NPF_{GUID}
   IPs: 192.168.1.100
2. Ethernet (Realtek PCIe GbE Family Controller)
   GUID: \Device\NPF_{GUID}
   IPs: No IP assigned
3. Loopback Pseudo-Interface 1
   GUID: \Device\NPF_Loopback
   IPs: 127.0.0.1
Enter the number of the interface to use:
```

---

## Output

* `report.html`: Interactive report with graphs and detailed findings
* `xids.log`: Log file for debug messages and system events

---

## Dependencies

* `torch`, `transformers`: BERT model
* `scapy` (v2.5.0+): Packet capture and parsing
* `plotly`, `networkx`, `jinja2`: Visualization and templating

Install all:

```bash
pip install torch transformers scapy plotly networkx jinja2
```

---

## Project Structure

```
xids/
├── r/                  # Snort rule files (.rules)
├── model_cache/        # Hugging Face model cache
├── uploads/            # Input PCAPs
├── xids.py             # Main detection script
├── xids.log            # Runtime logs
├── report.html         # Output report (example)
└── README.md
```

---

## Troubleshooting

* **No interfaces listed**

  * Ensure you're running as administrator (Windows)
  * Verify Npcap is installed and active:

    ```powershell
    sc query npcap
    ```

* **Error: `get_windows_if_list` not defined**

  * Upgrade Scapy:

    ```bash
    pip install --upgrade scapy
    ```

* **No packets captured during live sniffing**

  * Use a correct interface (with an active IP)
  * Validate BPF filter using Wireshark

* **PCAP fails to load**

  * Check PCAP format or path
  * Test:

    ```bash
    python -c "from scapy.all import rdpcap; print(len(rdpcap('uploads/portscan.pcap')))"
    ```

---

## Contributing

Feel free to open issues, suggest features, or submit pull requests. Contributions for new detection rules, visualizations, or performance improvements are welcome.

---

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

* [Scapy](https://scapy.net/)
* [Hugging Face Transformers](https://huggingface.co/)
* [Plotly](https://plotly.com/python/)
* [Snort Rules](https://www.snort.org/downloads)

---

*Packets don’t lie — but attackers try.*

```
