from Kitsune import Kitsune
import numpy as np
import time
import logging
from scapy.all import IP  # For packet parsing (requires adjustment in Kitsune)

# Configure logging for general traffic and anomaly detection
logging.basicConfig(level=logging.INFO)
traffic_logger = logging.getLogger('traffic')
anomaly_logger = logging.getLogger('anomaly')

# File handlers for logs (paths are Docker-compatible)
traffic_handler = logging.FileHandler('/app/logs/traffic.log')
anomaly_handler = logging.FileHandler('/app/logs/anomaly.log')

# Set log formats as JSON
class JsonFormatter(logging.Formatter):
    def format(self, record):
        import json
        from datetime import datetime
        record_dict = {
            'time': datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S.%f%z'),
            'level': record.levelname,
            'message': record.getMessage()
        }
        return json.dumps(record_dict)

formatter = JsonFormatter()
traffic_handler.setFormatter(formatter)
anomaly_handler.setFormatter(formatter)

# Add handlers to loggers
traffic_logger.addHandler(traffic_handler)
anomaly_logger.addHandler(anomaly_handler)

# KitNET parameters
maxAE = 10  # Maximum size for any autoencoder in the ensemble layer
FMgrace = 5000  # Feature mapping grace period (training ensemble architecture)
ADgrace = 50000  # Anomaly detector grace period (training the ensemble)

# Path to the PCAP file (mounted in Docker)
path = "/data/wifi.pcap"
packet_limit = np.Inf  # Process all packets in the file

# Initialize Kitsune with custom learning rate for robustness
K = Kitsune(path, packet_limit, maxAE, FMgrace, ADgrace, learning_rate=0.01, hidden_ratio=0.75)

import sys

def debug(msg):
    print(msg, file=sys.stderr, flush=True)

debug(f"Starting Kitsune with PCAP file: {path}")
debug(f"Parameters: maxAE={maxAE}, FMgrace={FMgrace}, ADgrace={ADgrace}")
debug("Checking if PCAP file exists...")
import os
if os.path.exists(path):
    debug(f"PCAP file found, size: {os.path.getsize(path)} bytes")
else:
    debug(f"ERROR: PCAP file not found at {path}")
debug("Running Kitsune on wifi.pcap...")
RMSEs = []
packet_count = 0
start_time = time.time()

# Process each packet in real-time
while True:
    packet_count += 1
    if packet_count % 1000 == 0:
        debug(f"Processed {packet_count} packets")
    
    # Process the next packet and get RMSE
    rmse = K.proc_next_packet()
    if rmse == -1:  # End of PCAP file
        break
    
    RMSEs.append(rmse)
    
    # Log general traffic details
    traffic_logger.info(f"Packet {packet_count}: RMSE={rmse:.6f}, Timestamp={time.time()}")
    
    # Dynamic threshold for anomaly detection (based on running stats)
    if packet_count > FMgrace + ADgrace:  # After training periods
        benign_rmse = RMSEs[FMgrace + ADgrace:packet_count]
        threshold = np.mean(benign_rmse) + 3 * np.std(benign_rmse)  # 3 standard deviations
        if rmse > threshold:
            # Hypothetical method to get current packet (requires Kitsune modification)
            packet = K.get_current_packet()  # Adjust Kitsune to expose this
            packet_time = packet.time if packet else time.time()
            src_ip = packet[IP].src if packet and IP in packet else "N/A"
            dst_ip = packet[IP].dst if packet and IP in packet else "N/A"
            protocol = packet.proto if packet and IP in packet else "N/A"
            anomaly_id = f"anomaly_{packet_count}"
            
            anomaly_logger.warning(
                f"Anomaly detected - ID={anomaly_id}, Packet={packet_count}, "
                f"RMSE={rmse:.6f}, Threshold={threshold:.6f}, "
                f"Deviation={(rmse - np.mean(benign_rmse)) / np.std(benign_rmse):.2f}σ, "
                f"Timestamp={packet_time}, SrcIP={src_ip}, DstIP={dst_ip}, Protocol={protocol}"
            )

# Calculate and display runtime
end_time = time.time()
print(f"Complete. Time elapsed: {end_time - start_time:.2f} seconds")

# Summary statistics for AI system analysis
if RMSEs:
    print(f"Total packets processed: {packet_count}")
    print(f"Average RMSE: {np.mean(RMSEs):.6f}")
    print(f"Max RMSE: {np.max(RMSEs):.6f}")