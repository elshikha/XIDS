import argparse
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from scapy.all import *
from scapy.arch.windows import get_windows_if_list  # Explicitly import Windows-specific function
import plotly.graph_objects as go
import plotly.io as pio
import networkx as nx
from scapy.all import IP, TCP
import os
import re
import glob
import logging
import signal
import sys
from datetime import datetime
from collections import defaultdict

# Set Plotly to render as HTML
pio.renderers.default = 'iframe'

# Define attack classes and their enriched descriptions
attack_descriptions = {
    'Analysis': 'Attempts to analyze network or system vulnerabilities, often using port scans or reconnaissance tools to identify weak points for exploitation. Common in early stages of advanced persistent threats (APTs).',
    'Backdoor': 'Unauthorized access via hidden entry points, allowing attackers to maintain control or exfiltrate data. Frequently linked to malware like Trojans.',
    'Bot': 'Automated malicious software in botnets, used for DDoS attacks or spam distribution. Recent trends show botnets evolving with AI-driven command-and-control.',
    'DDoS': 'Distributed Denial-of-Service attack that overwhelms network resources with traffic from multiple sources, disrupting service availability. A 2025 trend shows increased use of IoT botnets.',
    'DoS': 'Denial-of-Service attack to disrupt service, often targeting specific servers with high traffic volumes.',
    'DoS GoldenEye': 'A specific DoS attack targeting HTTP servers with aggressive request floods, noted in recent cloud security breaches.',
    'DoS Hulk': 'A DoS attack generating high volumes of HTTP traffic, exploiting server response mechanisms.',
    'DoS SlowHTTPTest': 'A slow DoS attack targeting HTTP servers by keeping connections open, exhausting resources over time.',
    'DoS Slowloris': 'A DoS attack that maintains open connections to exhaust server resources, commonly used against web applications.',
    'Exploits': 'Attempts to exploit software vulnerabilities, such as unpatched CVEs, to gain unauthorized access.',
    'FTP Patator': 'Brute-force attack targeting FTP services, attempting multiple login combinations to breach accounts.',
    'Fuzzers': 'Automated attacks sending random data to find vulnerabilities, often used in penetration testing gone rogue.',
    'Generic': 'Generic malicious activity not fitting specific categories, potentially indicating new or unclassified threats.',
    'Heartbleed': 'Exploitation of the OpenSSL Heartbleed vulnerability, allowing data leakage from affected systems.',
    'Infiltration': 'Unauthorized access to infiltrate a network, often through phishing or compromised credentials.',
    'Normal': 'Non-malicious, legitimate network traffic, serving as a baseline for anomaly detection.',
    'Port Scan': 'Scanning network ports to identify open services, a precursor to targeted attacks.',
    'Reconnaissance': 'Probing to gather information about a network, often the first step in a multi-stage attack.',
    'SSH Patator': 'Brute-force attack targeting SSH services, attempting to crack login credentials.',
    'Shellcode': 'Malicious code executed to gain control, typically delivered via exploits.',
    'Web Attack - Brute Force': 'Brute-force attack targeting web applications, often aiming at login pages.',
    'Web Attack - SQL Injection': 'Injection of malicious SQL queries into web forms, risking data breaches or server control.',
    'Web Attack - XSS': 'Cross-Site Scripting attack injecting malicious scripts, compromising user sessions.',
    'Worms': 'Self-replicating malware spreading across networks, causing widespread damage.'
}

classes = list(attack_descriptions.keys())

# Setup logging
logging.basicConfig(
    filename='xids.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load Snort rules from the 'r' folder
def load_snort_rules(rule_dir="r"):
    if not os.path.exists(rule_dir):
        logging.error(f"Rule directory {rule_dir} does not exist.")
        print(f"Error: Rule directory {rule_dir} does not exist.")
        return {}
    snort_rules = {}
    rule_files = glob.glob(os.path.join(rule_dir, "*.rules"))
    for rule_file in rule_files:
        attack_type = os.path.splitext(os.path.basename(rule_file))[0]
        with open(rule_file, 'r') as f:
            rules = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        if 'alert' in line and 'msg' in line and 'content' in line:
                            msg_match = re.search(r'msg:"(.*?)"', line)
                            content_match = re.search(r'content:"(.*?)"', line)
                            if msg_match and content_match:
                                msg = msg_match.group(1)
                                content = content_match.group(1)
                                pattern = re.compile(re.escape(content), re.IGNORECASE)
                                rules.append({
                                    'rule': line,
                                    'pattern': pattern
                                })
                    except Exception as e:
                        logging.error(f"Error parsing rule in {rule_file}: {e}")
                        print(f"Error parsing rule in {rule_file}: {e}")
            if rules:
                snort_rules[attack_type] = rules
    return snort_rules

snort_rules = load_snort_rules()

# Initialize model and tokenizer
try:
    tokenizer = AutoTokenizer.from_pretrained("rdpahalavan/bert-network-packet-flow-header-payload", cache_dir="./model_cache")
    model = AutoModelForSequenceClassification.from_pretrained("rdpahalavan/bert-network-packet-flow-header-payload", cache_dir="./model_cache")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
except Exception as e:
    logging.error(f"Error loading BERT model: {e}")
    print(f"Error: Failed to load BERT model: {e}")
    sys.exit(1)

# Global dictionaries for storing analysis results
packets_brief = {}
protocol_counts = {}
attack_timeline = defaultdict(list)  # Store timestamps for each attack type
ip_heatmap = defaultdict(int)  # Store src_ip -> dst_ip counts
packet_sizes = []  # Store packet lengths
packets_nbr = 0

def processing_packet_conversion(packet):
    try:
        if IP not in packet or TCP not in packet:
            return None, None
        ip = packet[IP]
        tcp = packet[TCP]
        payload = bytes(tcp.payload)
        header_info = f"src_ip:{ip.src} dst_ip:{ip.dst} src_port:{tcp.sport} dst_port:{tcp.dport}"
        payload_str = payload.hex()
        packet_str = f"{header_info} payload:{payload_str}"
        return packet_str, payload.decode('utf-8', errors='ignore')
    except Exception as e:
        logging.error(f"Error processing packet: {e}")
        return None, None

def apply_snort_rules(payload, packet):
    for attack_type, rules in snort_rules.items():
        for rule in rules:
            if rule['pattern'].search(payload):
                description = attack_descriptions.get(attack_type, "No description available")
                return attack_type, rule['rule'], description
    return None, None, None

def analyze_packet(packet, filter_bytes=b'', real_time=False):
    global packets_nbr
    if IP in packet and TCP in packet:
        payload_bytes = bytes(packet.payload)
        if filter_bytes in payload_bytes or not filter_bytes:
            packet_str, payload_text = processing_packet_conversion(packet)
            if packet_str:
                truncated_line = packet_str[:1024]
                tokens = tokenizer(truncated_line, return_tensors="pt", padding=True, truncation=True)
                tokens = {key: value.to(device) for key, value in tokens.items()}
                with torch.no_grad():
                    outputs = model(**tokens)
                logits = outputs.logits
                probabilities = logits.softmax(dim=1)
                predicted_class = torch.argmax(probabilities, dim=1).item()
                predicted_attack = classes[predicted_class]
                rule_based_attack, matched_rule, description = apply_snort_rules(payload_text, packet)
                timestamp = float(packet.time)  # Convert EDecimal to float
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_size = len(packet)
                
                if rule_based_attack:
                    packets_brief[rule_based_attack] = packets_brief.get(rule_based_attack, {'count': 0, 'source': 'Rule-Based', 'rules': [], 'description': description})
                    packets_brief[rule_based_attack]['count'] += 1
                    packets_brief[rule_based_attack]['source'] = 'Rule-Based'
                    if matched_rule and matched_rule not in packets_brief[rule_based_attack]['rules']:
                        packets_brief[rule_based_attack]['rules'].append(matched_rule)
                    attack_timeline[rule_based_attack].append(timestamp)
                    if real_time:
                        alert = f"[ALERT] Packet {packets_nbr}: Rule-Based detection: {rule_based_attack}, Rule: {matched_rule}, Description: {description}"
                        print(alert)
                        logging.info(alert)
                elif predicted_attack != "Normal":
                    packets_brief[predicted_attack] = packets_brief.get(predicted_attack, {'count': 0, 'source': 'BERT', 'rules': [], 'description': attack_descriptions.get(predicted_attack, 'No description available')})
                    packets_brief[predicted_attack]['count'] += 1
                    packets_brief[predicted_attack]['source'] = 'BERT'
                    attack_timeline[predicted_attack].append(timestamp)
                    if real_time:
                        alert = f"[ALERT] Packet {packets_nbr}: BERT Predicted class: {predicted_attack}, Description: {attack_descriptions.get(predicted_attack, 'No description available')}"
                        print(alert)
                        logging.info(alert)
                proto = packet[IP].proto
                protocol_counts[proto] = protocol_counts.get(proto, {'count': 0})
                protocol_counts[proto]['count'] += 1
                ip_heatmap[(src_ip, dst_ip)] += 1
                packet_sizes.append(packet_size)
                packets_nbr += 1

def process_pcap_file(pcap_file, filter_bytes):
    global packets_nbr
    packets_nbr = 0
    try:
        pcap = rdpcap(pcap_file)
        filtered_packets = []
        for pkt in pcap:
            if filter_bytes:
                payload_bytes = bytes(pkt.payload) if IP in pkt and TCP in pkt else b''
                if filter_bytes in payload_bytes:
                    analyze_packet(pkt, filter_bytes, real_time=False)
                    filtered_packets.append(pkt)
            else:
                analyze_packet(pkt, filter_bytes, real_time=False)
                filtered_packets.append(pkt)
        return filtered_packets
    except Exception as e:
        logging.error(f"Error processing PCAP file {pcap_file}: {e}")
        print(f"Error: Failed to process PCAP file {pcap_file}: {e}")
        sys.exit(1)

def list_interfaces():
    try:
        interfaces = get_if_list()
        if not interfaces:
            print("Error: No network interfaces found.")
            logging.error("No network interfaces found.")
            sys.exit(1)
        print("Available network interfaces:")
        interface_map = {}
        try:
            win_interfaces = get_windows_if_list()  # Get friendly names and details
            for i, iface in enumerate(interfaces, 1):
                friendly_name = "Unknown"
                description = "No description"
                ips = []
                # Find matching interface in win_interfaces
                for win_iface in win_interfaces:
                    if win_iface.get('guid', '').lower() in iface.lower():
                        friendly_name = win_iface.get('name', 'Unknown')
                        description = win_iface.get('description', 'No description')
                        ips = win_iface.get('ips', [])
                        break
                ip_str = ", ".join(ips) if ips else "No IP assigned"
                print(f"{i}. {friendly_name} ({description})")
                print(f"   GUID: {iface}")
                print(f"   IPs: {ip_str}")
                interface_map[i] = iface
        except Exception as e:
            logging.warning(f"Failed to get friendly interface names: {e}")
            print("Warning: Could not retrieve friendly interface names. Showing GUIDs only.")
            for i, iface in enumerate(interfaces, 1):
                print(f"{i}. {iface}")
                interface_map[i] = iface
        return interface_map
    except Exception as e:
        logging.error(f"Error listing interfaces: {e}")
        print(f"Error: Failed to list interfaces: {e}")
        sys.exit(1)

def select_interface():
    interface_map = list_interfaces()
    while True:
        try:
            choice = input("Enter the number of the interface to use: ")
            choice = int(choice)
            if choice in interface_map:
                return interface_map[choice]
            else:
                print(f"Please enter a number between 1 and {len(interface_map)}.")
        except ValueError:
            print("Please enter a valid number.")

def create_network_graph(packets, max_nodes=50):
    G = nx.DiGraph()
    node_count = 0
    for packet in packets:
        if IP in packet and node_count < max_nodes:
            src, dst = packet[IP].src, packet[IP].dst
            G.add_edge(src, dst)
            node_count += len(G.nodes) - node_count
    return G

def visualize_network_graph(packets):
    network_graph = create_network_graph(packets)
    pos = nx.spring_layout(network_graph)
    
    edge_x = []
    edge_y = []
    for edge in network_graph.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color='#888'),
        hoverinfo='none',
        mode='lines'
    )
    
    node_x = []
    node_y = []
    node_text = []
    for node in network_graph.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(node)
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=node_text,
        textposition="top center",
        marker=dict(
            showscale=False,
            color='#0d9488',
            size=10,
            line_width=2
        )
    )
    
    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title=dict(text='Network Endpoints', font=dict(size=16)),
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20, l=5, r=5, t=40),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                    ))
    
    return fig.to_html(full_html=False, include_plotlyjs='cdn')

def visualize_destination_ports_plot(packets, top_n=20):
    destination_ports = {}
    for packet in packets:
        if IP in packet and TCP in packet:
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            destination_ports[(dst_ip, dst_port)] = destination_ports.get((dst_ip, dst_port), 0) + 1
    
    sorted_ports = sorted(destination_ports.items(), key=lambda x: x[1], reverse=True)[:top_n]
    destinations, counts = zip(*sorted_ports)
    dst_labels = [f"{ip}:{port}" for (ip, port) in destinations]
    
    fig = go.Figure(data=[
        go.Bar(
            y=dst_labels,
            x=counts,
            orientation='h',
            marker=dict(color='#0d9488', line=dict(color='black', width=1)),
            text=counts,
            textposition='auto'
        )
    ])
    
    fig.update_layout(
        title='Top Contacted TCP Ports',
        xaxis_title='Count',
        yaxis_title='Destination IP:Port',
        yaxis=dict(autorange='reversed'),
        template='plotly_white',
        margin=dict(l=200, r=20, t=50, b=20),
        height=600
    )
    
    return fig.to_html(full_html=False, include_plotlyjs='cdn')

def visualize_attack_timeline():
    if not attack_timeline:
        return ''
    
    fig = go.Figure()
    for attack_type, timestamps in attack_timeline.items():
        valid_times = []
        for ts in timestamps:
            try:
                valid_times.append(datetime.fromtimestamp(float(ts)))
            except (ValueError, TypeError) as e:
                logging.warning(f"Skipping invalid timestamp for {attack_type}: {ts}, error: {e}")
                continue
        if valid_times:
            counts = list(range(1, len(valid_times) + 1))  # Cumulative count
            fig.add_trace(go.Scatter(
                x=valid_times,
                y=counts,
                mode='lines+markers',
                name=attack_type,
                line=dict(width=2),
                marker=dict(size=8)
            ))
    
    fig.update_layout(
        title='Attack Timeline',
        xaxis_title='Time',
        yaxis_title='Cumulative Packet Count',
        template='plotly_white',
        margin=dict(l=50, r=20, t=50, b=20),
        height=600
    )
    
    return fig.to_html(full_html=False, include_plotlyjs='cdn')

def visualize_ip_heatmap():
    if not ip_heatmap:
        return ''
    
    src_ips = sorted(set(src for src, _ in ip_heatmap.keys()))
    dst_ips = sorted(set(dst for _, dst in ip_heatmap.keys()))
    z = [[0] * len(dst_ips) for _ in range(len(src_ips))]
    
    for (src, dst), count in ip_heatmap.items():
        src_idx = src_ips.index(src)
        dst_idx = dst_ips.index(dst)
        z[src_idx][dst_idx] = count
    
    fig = go.Figure(data=go.Heatmap(
        z=z,
        x=dst_ips,
        y=src_ips,
        colorscale='Viridis',
        showscale=True
    ))
    
    fig.update_layout(
        title='Source to Destination IP Communication Heatmap',
        xaxis_title='Destination IP',
        yaxis_title='Source IP',
        template='plotly_white',
        margin=dict(l=100, r=20, t=50, b=20),
        height=600
    )
    
    return fig.to_html(full_html=False, include_plotlyjs='cdn')

def visualize_packet_size_distribution():
    if not packet_sizes:
        return ''
    
    fig = go.Figure(data=[
        go.Histogram(
            x=packet_sizes,
            nbinsx=50,
            marker=dict(color='#ff6b6b', line=dict(color='black', width=1)),
            opacity=0.75
        )
    ])
    
    fig.update_layout(
        title='Packet Size Distribution',
        xaxis_title='Packet Size (Bytes)',
        yaxis_title='Count',
        template='plotly_white',
        margin=dict(l=50, r=20, t=50, b=20),
        height=600
    )
    
    return fig.to_html(full_html=False, include_plotlyjs='cdn')

def generate_html_output(output_file, packets):
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Traffic Analysis Results</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {
            background: linear-gradient(135deg, #1e3a8a, #6b7280);
            font-family: 'Inter', sans-serif;
            color: #e5e7eb;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 1rem;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            padding: 3rem;
        }
        .alert {
            padding: 1.5rem;
            border-radius: 0.5rem;
            margin-bottom: 1.5rem;
        }
        .graph-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 2rem;
            margin-top: 2rem;
        }
        table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; }
        th, td { padding: 1rem; text-align: left; border-bottom: 1px solid #e5e7eb; color: #000; }
        th { background-color: #f3f4f6; color: #000; font-weight: bold; }
        .description { font-size: 0.9rem; color: #4b5563; margin-top: 0.5rem; line-height: 1.5; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1 class="text-4xl font-extrabold text-gray-900 mb-8 text-center">Network Traffic Analysis Results</h1>
            <div class="alert" style="background-color: {{ alert_color }}; color: {{ alert_text_color }}">
                <p class="font-semibold text-lg">{{ alert_text }}</p>
            </div>
            {% if packets_brief %}
                <h2 class="text-2xl font-semibold text-gray-800 mt-6 mb-4">Malicious Activity Details</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Attack Type</th>
                            <th>Packet Count</th>
                            <th>Source</th>
                            <th>Snort Rule</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for attack, details in packets_brief.items() %}
                            <tr>
                                <td>{{ attack }}</td>
                                <td>{{ details.count }}</td>
                                <td>{{ details.source }}</td>
                                <td>
                                    {% if details.rules %}
                                        {% for rule in details.rules %}
                                            <span>{{ rule }}</span><br>
                                        {% endfor %}
                                    {% else %}
                                        N/A
                                    {% endif %}
                                </td>
                                <td>{{ details.description }}</td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% endif %}
            <div class="graph-container">
                {% if graph1 %}
                    <div>
                        <h2 class="text-xl font-semibold text-gray-800 mb-2">Attack Timeline</h2>
                        {{ graph1 | safe }}
                        <p class="description">This timeline shows when malicious activities were detected, helping identify attack patterns over time.</p>
                    </div>
                {% endif %}
                {% if graph2 %}
                    <div>
                        <h2 class="text-xl font-semibold text-gray-800 mb-2">Source to Destination IP Communication</h2>
                        {{ graph2 | safe }}
                        <p class="description">This heatmap shows packet counts between source and destination IPs, highlighting key communication patterns.</p>
                    </div>
                {% endif %}
                {% if graph3 %}
                    <div>
                        <h2 class="text-xl font-semibold text-gray-800 mb-2">Network Endpoints</h2>
                        {{ graph3 | safe }}
                        <p class="description">This graph maps communication paths between IPs, revealing potential infiltration points.</p>
                    </div>
                {% endif %}
                {% if graph4 %}
                    <div>
                        <h2 class="text-xl font-semibold text-gray-800 mb-2">TCP Ports</h2>
                        {{ graph4 | safe }}
                        <p class="description">This graph shows the most contacted TCP ports, guiding firewall adjustments.</p>
                    </div>
                {% endif %}
                {% if graph5 %}
                    <div>
                        <h2 class="text-xl font-semibold text-gray-800 mb-2">Packet Size Distribution</h2>
                        {{ graph5 | safe }}
                        <p class="description">This histogram shows the distribution of packet sizes, helping identify anomalies like large payloads.</p>
                    </div>
                {% endif %}
            </div>
        </div>
    </div>
</body>
</html>
"""
    from jinja2 import Template
    alert_color = "#c0392b" if packets_brief else "#27ae60"
    alert_text_color = "#fff" if packets_brief else "#000"
    alert_text = "Malicious network activity detected!" if packets_brief else "No malicious activity detected."
    graph1 = visualize_attack_timeline() if attack_timeline else ''
    graph2 = visualize_ip_heatmap() if ip_heatmap else ''
    graph3 = visualize_network_graph(packets) if packets else ''
    graph4 = visualize_destination_ports_plot(packets) if packets else ''
    graph5 = visualize_packet_size_distribution() if packet_sizes else ''
    
    template = Template(html_content)
    rendered_html = template.render(
        alert_color=alert_color,
        alert_text_color=alert_text_color,
        alert_text=alert_text,
        packets_brief=packets_brief,
        graph1=graph1,
        graph2=graph2,
        graph3=graph3,
        graph4=graph4,
        graph5=graph5
    )
    
    try:
        with open(output_file, 'w') as f:
            f.write(rendered_html)
        print(f"Analysis complete. Results written to {output_file}")
        logging.info(f"Results written to {output_file}")
    except Exception as e:
        logging.error(f"Error writing to {output_file}: {e}")
        print(f"Error: Failed to write to {output_file}: {e}")
        sys.exit(1)

def signal_handler(sig, frame):
    print("\n[INFO] Stopping live capture...")
    if captured_packets:
        generate_html_output(args.output, captured_packets)
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XIDS: Network Traffic Analyzer")
    parser.add_argument("-f", "--file", help="Path to PCAP file")
    parser.add_argument("-o", "--output", required=True, help="Output HTML file")
    parser.add_argument("--filter", default="", help="Filter: byte sequence for PCAP files, BPF syntax for live capture (e.g., 'tcp port 80')")
    args = parser.parse_args()

    captured_packets = []
    packets_brief.clear()
    protocol_counts.clear()
    attack_timeline.clear()
    ip_heatmap.clear()
    packet_sizes.clear()
    packets_nbr = 0

    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: PCAP file {args.file} does not exist.")
            sys.exit(1)
        if not args.file.lower().endswith(('.pcap', '.pcapng')):
            print("Error: File must be a .pcap or .pcapng file.")
            sys.exit(1)
        print(f"Processing PCAP file: {args.file}")
        logging.info(f"Processing PCAP file: {args.file}")
        captured_packets = process_pcap_file(args.file, args.filter.encode('utf-8') if args.filter else b'')
        generate_html_output(args.output, captured_packets)
    else:
        signal.signal(signal.SIGINT, signal_handler)
        interface = select_interface()
        print(f"Starting live capture on interface: {interface}")
        logging.info(f"Starting live capture on interface: {interface}")
        try:
            sniff(iface=interface, filter=args.filter if args.filter else None, prn=lambda pkt: (analyze_packet(pkt, b'', real_time=True), captured_packets.append(pkt)), store=0)
        except Exception as e:
            logging.error(f"Error during live capture on {interface}: {e}")
            print(f"Error: Failed to capture on {interface}: {e}")
            sys.exit(1)