# XIDS: Network Traffic Analyzer

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**XIDS** (eXperimental Intrusion Detection System) is a Python tool that sniffs out sneaky network threats like a firewall with attitude! 🔥 It analyzes PCAP files or live traffic, using BERT and Snort rules to detect attacks (e.g., DDoS, SQL Injection). Results are displayed in a slick HTML report with five interactive Plotly graphs. Perfect for security geeks and network admins!

## Features

- **BERT + Snort Detection**: Uses a BERT model and Snort rules to catch 24 attack types.
- **Five Cool Graphs**: Attack Timeline, IP Heatmap, Network Endpoints, TCP Ports, Packet Size Distribution.
- **Flexible Filtering**: Filter PCAPs by byte sequences (e.g., `GET`) or live traffic by BPF (e.g., `tcp port 80`).
- **User-Friendly**: Shows network interfaces with names like "Wi-Fi" or "Ethernet" (not just cryptic GUIDs!).
- **HTML Output**: Generates a fancy report with Tailwind CSS and Plotly graphs.

## Installation

1. **Clone the Repo**:
   ```bash
   git clone https://github.com/yourusername/xids.git
   cd xids
   ```

2. **Install Dependencies**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install torch transformers scapy plotly networkx jinja2
   ```

3. **Install Npcap (Windows)**:
   - Download from [npcap.com](https://npcap.com/).
   - Check “Support loopback traffic” and “WinPcap API-compatible mode”.

4. **Add Snort Rules**:
   - Create an `r` folder in the project root.
   - Add `.rules` files (e.g., `ddos.rules`):
     ```
     alert tcp any any -> any 80 (msg:"SQL Injection"; content:"SELECT * FROM"; nocase; sid:1000001;)
     ```

5. **Run as Admin (Windows)**:
   ```powershell
   Start-Process powershell -Verb RunAs
   ```

## Usage

### Analyze a PCAP File
```bash
python xids.py -f uploads/portscan.pcap -o report.html --filter "GET"
```
- `-f`: PCAP file path.
- `-o`: Output HTML file.
- `--filter`: Optional byte sequence (e.g., `GET` for HTTP). Omit for all packets.

### Live Packet Capture
```bash
python xids.py -o report.html --filter "tcp port 80"
```
- `-o`: Output HTML file.
- `--filter`: Optional BPF filter (e.g., `tcp port 80`). Omit for all packets.
- Select an interface from the list (e.g., `1` for Wi-Fi). Press `Ctrl+C` to stop.

**Interface Example**:
```
Available network interfaces:
1. Wi-Fi (Intel(R) Wireless-AC 9560)
   GUID: \Device\NPF_{81CAC0B1-E7F3-402D-A120-25033FD98BCC}
   IPs: 192.168.1.100
2. Ethernet (Realtek PCIe GbE Family Controller)
   GUID: \Device\NPF_{C6C5DCDD-3C80-486B-AE29-3062C509C4CB}
   IPs: No IP assigned
3. Loopback Pseudo-Interface 1
   GUID: \Device\NPF_Loopback
   IPs: 127.0.0.1
Enter the number of the interface to use:
```

## Output

- **HTML Report** (`report.html`): Includes a table of detected attacks and five interactive graphs.
- **Logs**: Check `xids.log` for debugging.

## Dependencies

- `torch`, `transformers`: For BERT model.
- `scapy` (2.5.0+): For packet capture.
- `plotly`, `networkx`, `jinja2`: For graphs and HTML.

Install:
```bash
pip install torch transformers scapy plotly networkx jinja2
```

## Project Structure

```
xids/
├── r/                    # Snort .rules files
├── model_cache/          # BERT model cache
├── xids.py               # Main script
├── xids.log              # Logs
├── uploads/              # PCAP files (e.g., portscan.pcap)
├── report.html           # Output report
└── README.md             # This file
```

## Troubleshooting

- **Error: `get_windows_if_list` not defined**:
  - Upgrade `scapy`:
    ```bash
    pip install --upgrade scapy
    ```
  - Reinstall Npcap from [npcap.com](https://npcap.com/).

- **No interfaces listed**:
  - Run as Administrator:
    ```powershell
    Start-Process powershell -Verb RunAs
    ```
  - Check Npcap service:
    ```powershell
    sc query npcap
    ```

- **No packets captured**:
  - Ensure the interface has an IP (e.g., `192.168.1.100`).
  - Test BPF filter in Wireshark (e.g., `tcp port 80`).

- **PCAP errors**:
  - Verify file:
    ```bash
    python -c "from scapy.all import rdpcap; print(len(rdpcap('uploads/portscan.pcap')))"
    ```
  - Check `xids.log`.

## Contributing

Got ideas to make XIDS cooler? 😎 Fork, branch, commit, and open a Pull Request. Add some packet-sniffing humor for bonus points!

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgements

- **Scapy**, **Hugging Face**, **Plotly**, **Snort**: For powering XIDS.
- **You**: For battling network threats like a pro! 🦸‍♂️

*“Packets don’t lie, but hackers try!”* 🚀
```

---

### **How to Use the README**
1. **Copy the Content**:
   - Copy the entire Markdown content above (from `# XIDS: Network Traffic Analyzer` to the end).
   - Ensure no extra spaces or characters are included.

2. **Create `README.md`**:
   - Navigate to your project directory:
     ```powershell
     cd "D:\XIDS project\FirstTry"
     ```
   - Create and edit `README.md`:
     ```powershell
     notepad README.md
     ```
   - Paste the copied content and save.

3. **Update Repository URL**:
   - Replace `yourusername/xids` with your GitHub username and repository name (e.g., `elshimy/xids`).
     - In badges: `https://img.shields.io/github/issues/yourusername/xids`
     - In clone command: `git clone https://github.com/yourusername/xids.git`
   - Use a text editor (e.g., VS Code) to make these changes.

4. **Add a License (Optional)**:
   - The README assumes an MIT License. Create a `LICENSE` file:
     ```powershell
     notepad LICENSE
     ```
   - Paste:
     ```
     MIT License

     Copyright (c) 2025 [Your Name]

     Permission is hereby granted, free of charge, to any person obtaining a copy
     of this software and associated documentation files (the "Software"), to deal
     in the Software without restriction, including without limitation the rights
     to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
     copies of the Software, and to permit persons to whom the Software is
     furnished to do so, subject to the following conditions:

     The above copyright notice and this permission notice shall be included in all
     copies or substantial portions of the Software.

     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
     IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
     FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
     AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
     LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
     OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
     SOFTWARE.
     ```
   - Replace `[Your Name]` with your name or GitHub handle.

5. **Push to GitHub**:
   - Initialize a Git repository (if not already done):
     ```powershell
     cd "D:\XIDS project\FirstTry"
     git init
     ```
   - Add files:
     ```powershell
     git add README.md xids.py
     git add r/*.rules  # If you have Snort rules
     git add uploads/*.pcap  # If you have PCAP files
     ```
   - Commit and push:
     ```powershell
     git commit -m "Add XIDS script and README"
     git remote add origin https://github.com/yourusername/xids.git
     git push -u origin main
     ```
   - Replace `yourusername/xids` with your repository URL.
   - If the repository doesn’t exist, create it on GitHub first:
     - Go to [github.com](https://github.com), click “New repository,” name it (e.g., `xids`), and follow the setup instructions.

6. **Verify on GitHub**:
   - Visit your repository (e.g., `https://github.com/yourusername/xids`).
   - Check that the README renders with badges, headings, and code blocks.
   - Ensure links (e.g., Npcap, license) work.

---

### **Addressing Your Concerns**
- **Interface Clarity**: The README explains the interface selection process, showing friendly names (e.g., “Wi-Fi”) and IPs, addressing your earlier question about making interfaces understandable (`is there any way to show the interface in away that the user can know what is this interface?`). The updated `xids.py` (from my previous response) uses `get_windows_if_list` with a fallback to GUIDs.
- **Previous Errors**:
  - **EDecimal Error**: Fixed in `xids.py` with `float(packet.time)` (already included in the latest version).
  - **get_windows_if_list Error**: The README’s troubleshooting section covers upgrading `scapy` and reinstalling Npcap, based on your error (`Error: Failed to list interfaces: name 'get_windows_if_list' is not defined`).
- **Filter Option**: The Usage section includes examples for `--filter` (e.g., `GET` for PCAP, `tcp port 80` for live capture), drawing from your interest in filtering (July 24, 2025, 15:47 conversation).
- **Humor and Style**: Kept networking humor (e.g., “firewall with attitude”, “packets don’t lie”) to match your preference for engaging documentation.

---

### **Testing the Project**
To ensure `xids.py` works with the README:
1. **Use the Latest `xids.py`**:
   - Copy the `xids.py` from my previous response (artifact ID `99ec5d48-0530-41c7-8a04-023e93ceab21`, version `0c874dec-8824-4381-90bc-c71a29bd2e7c`), which fixes the `get_windows_if_list` error.
   - Save it to `D:\XIDS project\FirstTry\xids.py`.

2. **Test PCAP Analysis**:
   ```powershell
   python xids.py -f "D:\XIDS project\FirstTry\uploads\portscan.pcap" -o report.html
   ```
   - This should process `portscan.pcap` and generate `report.html` with graphs.

3. **Test Live Capture**:
   ```powershell
   Start-Process powershell -Verb RunAs
   python xids.py -o report.html --filter "tcp port 80"
   ```
   - Select an interface (e.g., `1` for Wi-Fi). Check for friendly names or GUIDs.
   - Press `Ctrl+C` to stop and generate `report.html`.

4. **Check Logs**:
   - If errors occur, view `xids.log`:
     ```powershell
     Get-Content xids.log
     ```
