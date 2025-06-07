# DDoS Simulation and Detection with Proof of Work

## Overview
This project simulates a DDoS attack using Mininet, captures network traffic, extracts features with nfstream, clusters traffic to identify attackers using KMeans, and applies a Proof of Work (PoW) mechanism with dynamic difficulty to mitigate attacks. Reputation scores are maintained for IPs, and results are visualized.

## Prerequisites
- Ubuntu or compatible Linux OS
- Python 3
- Required tools and libraries:
  - `tcpdump`
  - `hping3`
  - Python packages: `nfstream`, `mininet`, `pandas`, `numpy`, `scikit-learn`, `matplotlib`

## Installation
Run the following command to install dependencies:
```bash
sudo apt-get update && sudo apt-get install -y tcpdump hping3 && sudo pip3 install nfstream mininet pandas numpy scikit-learn matplotlib
```

## Usage
1. Save the script as `simulator_script.py`.
2. Run the script with elevated privileges:
   ```bash
   sudo python3 simulator_script.py
   ```
3. The script will:
   - Set up a Mininet topology with 1 victim, 50 attackers, and 50 normal hosts.
   - Simulate attack (UDP flood) and normal (TCP SYN) traffic.
   - Capture traffic using `tcpdump` and save to `victim.pcap`.
   - Extract features using `nfstream`.
   - Cluster traffic using KMeans to identify attackers.
   - Apply PoW with dynamic difficulty based on traffic volume.
   - Update and save IP reputation scores to `reputation.csv`.
   - Save flow data to `flows.csv`.
   - Generate a clustering plot in `clusters.png`.

## Proof of Work (PoW)
- **Dynamic Difficulty**: Calculated as `min(5, max(1, int(flow_bytes_s / 1000000 + flow_pkts_s / 1000)))`.
  - `flow_bytes_s / 1,000,000`: Estimates megabytes/sec.
  - `flow_pkts_s / 1,000`: Estimates packets/sec (1 difficulty level per 1,000 packets/sec).
  - Difficulty is clamped between 1 (low traffic) and 5 (high traffic).
- IPs in the attack cluster undergo PoW, with difficulty based on traffic intensity.
- Successful PoW increases reputation; failure decreases it.

## Outputs
- **reputation.csv**: IP addresses with initial and updated reputation scores.
- **flows.csv**: Aggregated flow data with clustering results.
- **clusters.png**: Scatter plot of flow_bytes_s vs. flow_pkts_s, colored by cluster.

## Notes
- Ensure sufficient permissions to run Mininet and `tcpdump`.
- The script requires significant computational resources due to the large topology and traffic generation.
- Clustering accuracy is reported as IP-based accuracy in the console output.

## Requirements
- Python 3.6+
- Mininet (tested with version 2.3.0)
- nfstream (tested with version 6.x)
- Hardware: At least 4GB RAM and 2 CPU cores recommended for smooth operation.