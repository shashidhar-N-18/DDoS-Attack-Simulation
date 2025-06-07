
import os
from time import sleep
import hashlib
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSController
from mininet.util import dumpNodeConnections
import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from nfstream import NFStreamer
import subprocess
from math import exp, floor

# Define Mininet topology with a single central switch
class LargeDDoSTopo(Topo):
    def build(self):
        victim = self.addHost('victim')
        attackers = [self.addHost(f'attacker{i+1}') for i in range(50)]
        normals = [self.addHost(f'normal{i+1}') for i in range(50)]
        switch = self.addSwitch('s1')
        self.addLink(victim, switch)
        for attacker in attackers:
            self.addLink(attacker, switch)
        for normal in normals:
            self.addLink(normal, switch)

# Function to extract features from pcap file using nfstream
def extract_features(pcap_file):
    try:
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"Pcap file {pcap_file} not found")
        print(f"Reading pcap file: {pcap_file}")
        streamer = NFStreamer(source=pcap_file, statistical_analysis=True)
        flows = []
        flow_count = 0
        for flow in streamer:
            flow_count += 1
            pkt_sizes = [flow.bidirectional_min_ps, flow.bidirectional_mean_ps, flow.bidirectional_max_ps]
            pkt_size_var = float(np.var(pkt_sizes)) if len(pkt_sizes) > 1 else 0.0
            protocol = 1 if flow.protocol == 17 else 0 if flow.protocol == 6 else -1
            flows.append({
                'src': flow.src_ip,
                'dst': flow.dst_ip,
                'flow_bytes_s': flow.bidirectional_bytes / max(flow.bidirectional_duration_ms / 1000.0, 1e-6),
                'flow_pkts_s': flow.bidirectional_packets / max(flow.bidirectional_duration_ms / 1000.0, 1e-6),
                'duration': flow.bidirectional_duration_ms / 1000.0,
                'pkt_size_var': pkt_size_var,
                'protocol': protocol,
                'dst_port': flow.dst_port
            })
        print(f"Total flows extracted: {flow_count}")
        if not flows:
            print("No flows extracted from pcap file")
            return pd.DataFrame()
        df = pd.DataFrame(flows)
        # Aggregate flows by src and dst
        df = df.groupby(['src', 'dst']).agg({
            'flow_bytes_s': 'mean',
            'flow_pkts_s': 'mean',
            'duration': 'sum',
            'pkt_size_var': 'mean',
            'protocol': 'max',
            'dst_port': 'mean'
        }).reset_index()
        print(f"Extracted {len(df)} aggregated flows")
        return df
    except Exception as e:
        print(f"Error processing pcap file: {e}")
        return pd.DataFrame()

# Proof of Work logic with dynamic difficulty using normal curve
def proof_of_work(attacker_ip, reputation):
    nonce = 0
    sigma = 25
    difficulty = floor(1 + exp(-((reputation - 50) ** 2) / (2 * sigma ** 2)))
    target = '0' * difficulty
    print(f"PoW difficulty for reputation {reputation}: {difficulty} zeros")
    while True:
        input_str = f"{attacker_ip}{nonce}".encode()
        hash_result = hashlib.sha256(input_str).hexdigest()
        if hash_result.startswith(target):
            print(f"Found valid nonce {nonce} for hash {hash_result}")
            return nonce
        nonce += 1
        if nonce > 100000:
            print(f"Failed to find nonce after {nonce} attempts")
            return -1

# Function to update reputation based on PoW results
def update_reputation(ip, success, reputation_dict):
    if ip not in reputation_dict:
        reputation_dict[ip] = {'initial': 50, 'updated': 50}
        print(f"Initialized reputation for {ip} to 50")
    if success:
        reputation_dict[ip]['updated'] += 5
    else:
        reputation_dict[ip]['updated'] -= 5
    reputation_dict[ip]['updated'] = max(min(reputation_dict[ip]['updated'], 100), 0)
    return reputation_dict[ip]['updated']

# Function to save reputation scores to CSV
def save_reputation_to_csv(reputation_dict):
    data = [{'IP': ip, 'Initial_Reputation': info['initial'], 'Updated_Reputation': info['updated']}
            for ip, info in reputation_dict.items()]
    df = pd.DataFrame(data)
    df.to_csv('reputation.csv', index=False)
    print("Reputation scores saved to 'reputation.csv'")

# Function to initialize or load reputation CSV
def initialize_reputation_csv(attacker_ips, normal_ips):
    all_ips = attacker_ips + normal_ips
    if os.path.exists('reputation.csv'):
        df = pd.read_csv('reputation.csv')
        existing_ips = set(df['IP'])
        missing_ips = [ip for ip in all_ips if ip not in existing_ips]
        if missing_ips:
            new_data = [{'IP': ip, 'Initial_Reputation': 50, 'Updated_Reputation': 50} for ip in missing_ips]
            df = pd.concat([df, pd.DataFrame(new_data)], ignore_index=True)
            df.to_csv('reputation.csv', index=False)
        print("Loaded and updated reputation.csv")
    else:
        data = [{'IP': ip, 'Initial_Reputation': 50, 'Updated_Reputation': 50} for ip in all_ips]
        df = pd.DataFrame(data)
        df.to_csv('reputation.csv', index=False)
        print("Initialized reputation.csv with all IPs")
    return df

# Function to check if required tools are installed
def check_dependencies():
    tools = ['tcpdump', 'hping3']
    missing = []
    for tool in tools:
        result = subprocess.run(['which', tool], capture_output=True, text=True)
        if result.returncode != 0:
            missing.append(tool)
    if missing:
        raise EnvironmentError(f"Missing dependencies: {', '.join(missing)}. Please install them.")
    try:
        import nfstream
    except ImportError:
        raise EnvironmentError("nfstream is not installed. Install with 'pip install nfstream'.")

def run():
    try:
        check_dependencies()
    except EnvironmentError as e:
        print(e)
        return

    topo = LargeDDoSTopo()
    net = Mininet(topo=topo, controller=OVSController)
    try:
        net.start()
        dumpNodeConnections(net.hosts)
        victim = net.get('victim')
        victim.setIP("10.0.0.100")
        attackers = [net.get(f'attacker{i+1}') for i in range(50)]
        normals = [net.get(f'normal{i+1}') for i in range(50)]
        victim_ip = "10.0.0.100"
        attacker_ips = [f"10.0.0.{i+1}" for i in range(50)]
        normal_ips = [f"10.0.0.{i+51}" for i in range(49)]
        for i, h in enumerate(attackers):
            h.setIP(f"10.0.0.{i+1}")
        for i, h in enumerate(normals):
            h.setIP(f"10.0.0.{i+51}")
        reputation_df = initialize_reputation_csv(attacker_ips, normal_ips)
        reputation_dict = {row['IP']: {'initial': row['Initial_Reputation'], 'updated': row['Updated_Reputation']}
                          for _, row in reputation_df.iterrows()}
        switch = net.get('s1')
        switch.cmd("ovs-ofctl add-flow s1 action=normal")
        print("Testing connectivity from attacker1 to victim...")
        result = attackers[0].cmd(f"ping -c 2 {victim_ip}")
        print(f"Ping result: {result}")
        if "2 packets transmitted, 2 received" not in result:
            print("Warning: Connectivity test failed. Traffic may not reach victim.")
        pcap_file = "victim.pcap"
        try:
            with open(pcap_file, 'w') as f:
                pass
            os.remove(pcap_file)
        except PermissionError:
            print("Error: No permission to write victim.pcap")
            return
        victim_intf = victim.intfList()[0].name
        print(f"Starting tcpdump on victim interface {victim_intf}...")
        victim.cmd(f"tcpdump -i {victim_intf} ip -w {pcap_file} &")
        sleep(2)
        tcpdump_check = victim.cmd("pgrep -f tcpdump")
        if not tcpdump_check.strip():
            print("Error: tcpdump is not running")
            return
        print("Sending attack traffic (using hping3 UDP flood)...")
        for h in attackers:
            h.cmd(f"timeout 20 hping3 --udp --flood -d 1400 {victim_ip} &")
        print("Sending normal traffic (using hping3 TCP SYN)...")
        for i, h in enumerate(normals):
            h.cmd(f"timeout 20 hping3 --syn -c 1000 -d 40 -p 80 {victim_ip} &")
        print("Capturing traffic for 30 seconds...")
        sleep(30)
        print("Stopping tcpdump and other processes...")
        victim.cmd("pkill -f tcpdump")
        victim.cmd("pkill -f hping3")
        for h in attackers + normals:
            h.cmd("pkill -f hping3")
        if not os.path.exists(pcap_file):
            print(f"Error: {pcap_file} was not created")
            return
        pcap_size = os.path.getsize(pcap_file)
        print(f"Pcap file size: {pcap_size} bytes")
        if pcap_size < 100:
            print("Warning: Pcap file is nearly empty. No significant traffic captured.")
        print("Extracting features from captured traffic...")
        df = extract_features(pcap_file)
        print(df)
        if df.empty or len(df) < 2:
            print("Insufficient data for clustering. Exiting...")
            return
        df = df[df['dst'] == victim_ip]
        print(f"Filtered {len(df)} flows to victim ({victim_ip})")
        print(f"Attacker flows: {len(df[df['src'].isin(attacker_ips)])}")
        print(f"Normal flows: {len(df[df['src'].isin(normal_ips)])}")
        attacker_mean = df[df['src'].isin(attacker_ips)]['flow_bytes_s'].mean()
        normal_mean = df[df['src'].isin(normal_ips)]['flow_bytes_s'].mean()
        print(f"Mean flow_bytes_s (attackers): {attacker_mean if not pd.isna(attacker_mean) else 'N/A'}")
        print(f"Mean flow_bytes_s (normals): {normal_mean if not pd.isna(normal_mean) else 'N/A'}")
        features = ['flow_bytes_s', 'flow_pkts_s', 'duration', 'pkt_size_var', 'protocol', 'dst_port']
        X = df[features].values
        # Weight protocol and dst_port higher
        weights = np.array([1, 1, 1, 1, 10, 5])
        X = X * weights
        scaler = StandardScaler()
        X_normalized = scaler.fit_transform(X)
        print("Running KMeans clustering...")
        kmeans = KMeans(n_clusters=2, random_state=42)
        df['cluster'] = kmeans.fit_predict(X_normalized)
        cluster0_bytes = df[df['cluster'] == 0]['flow_bytes_s'].mean()
        cluster1_bytes = df[df['cluster'] == 1]['flow_bytes_s'].mean()
        if cluster0_bytes > cluster1_bytes:
            df['cluster'] = 1 - df['cluster']
            print("Swapped cluster labels to ensure Cluster 1 is attackers")
        print("\nClustering Results:")
        print(df[['src', 'dst', 'flow_bytes_s', 'flow_pkts_s', 'duration', 'pkt_size_var', 'protocol', 'dst_port', 'cluster']])
        print(f"Cluster 0 size: {len(df[df['cluster'] == 0])}")
        print(f"Cluster 1 size: {len(df[df['cluster'] == 1])}")
        print(f"Attackers in Cluster 1: {len(df[(df['cluster'] == 1) & (df['src'].isin(attacker_ips))])}")
        print(f"Normals in Cluster 1: {len(df[(df['cluster'] == 1) & (df['src'].isin(normal_ips))])}")
        # Log cluster statistics
        print("\nCluster Statistics:")
        for cluster in [0, 1]:
            cluster_df = df[df['cluster'] == cluster]
            print(f"Cluster {cluster} stats:")
            print(f"  Mean flow_bytes_s: {cluster_df['flow_bytes_s'].mean()}")
            print(f"  Mean flow_pkts_s: {cluster_df['flow_pkts_s'].mean()}")
            print(f"  Mean duration: {cluster_df['duration'].mean()}")
            print(f"  Mean pkt_size_var: {cluster_df['pkt_size_var'].mean()}")
            print(f"  Mean protocol: {cluster_df['protocol'].mean()}")
            print(f"  Mean dst_port: {cluster_df['dst_port'].mean()}")
        print("\nSaving flow data to flows.csv")
        df.to_csv("flows.csv", index=False)
        attack_cluster = df[df['cluster'] == 1]
        print("Flow counts per IP in attack cluster:", attack_cluster['src'].value_counts().to_dict())
        processed_ips = set()
        for ip in attack_cluster['src'].unique():
            if ip == victim_ip or ip not in attacker_ips:
                continue
            if ip in processed_ips:
                print(f"Skipping duplicate IP {ip}")
                continue
            processed_ips.add(ip)
            print(f"Performing PoW for attacker {ip}...")
            reputation = reputation_dict.get(ip, {'initial': 50, 'updated': 50})['updated']
            nonce = proof_of_work(ip, reputation)
            success = nonce >= 0
            print(f"Attacker {ip} {'solved' if success else 'failed'} PoW with nonce: {nonce}")
            reputation = update_reputation(ip, success, reputation_dict)
            print(f"Reputation of {ip} is now {reputation}")
            save_reputation_to_csv(reputation_dict)
        save_reputation_to_csv(reputation_dict)
        # IP-based accuracy
        unique_ips = df['src'].unique()
        true_positives = len(df[(df['cluster'] == 1) & (df['src'].isin(attacker_ips))]['src'].unique())
        false_positives = len(df[(df['cluster'] == 1) & (df['src'].isin(normal_ips))]['src'].unique())
        false_negatives = len(df[(df['cluster'] == 0) & (df['src'].isin(attacker_ips))]['src'].unique())
        true_negatives = len(df[(df['cluster'] == 0) & (df['src'].isin(normal_ips))]['src'].unique())
        accuracy = (true_positives + true_negatives) / len(unique_ips) if len(unique_ips) > 0 else 0
        print(f"IP-based Accuracy: {accuracy * 100:.2f}%")
        plt.scatter(df['flow_bytes_s'], df['flow_pkts_s'], c=df['cluster'], cmap='viridis')
        plt.xlabel('Bytes/sec')
        plt.ylabel('Pkts/sec')
        plt.title('Flow Clustering')
        plt.grid(True)
        plt.savefig("clusters.png")
        print("Clustering plot saved to 'clusters.png'")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Cleaning up network...")
        net.stop()

if __name__ == '__main__':
    run()

