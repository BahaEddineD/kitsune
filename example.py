from Kitsune import Kitsune
import numpy as np
import time
import logging
from scapy.all import IP  # For packet parsing (requires adjustment in Kitsune)

# Configure logging for general traffic and anomaly detection
class JsonFormatter(logging.Formatter):
    def format(self, record):
        record_dict = {
            'time': datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S.%f%z'),
            'level': record.levelname,
            'message': record.getMessage()
        }
        return json.dumps(record_dict)

class KitsuneMonitor:
    def __init__(self):
        self.setup_logging()
        self.running = True
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        signal.signal(signal.SIGINT, self.handle_shutdown)

        # Path to the PCAP chunks directory (mounted in Docker)
        self.pcap_dir = "/data/pcap-chunks"

        # Kitsune parameters
        self.packet_limit = np.Inf
        self.maxAE = 10
        self.FMgrace = 5000
        self.ADgrace = 50000
        self.learning_rate = 0.01
        self.hidden_ratio = 0.75
        self.anomaly_threshold = 0.1

        # Function to get the latest PCAP file
        def get_latest_pcap():
            try:
                pcap_files = glob.glob(f"{self.pcap_dir}/*.pcap")
                if not pcap_files:
                    self.logger.debug(f"No PCAP files found in {self.pcap_dir}")
                    return None
                latest = max(pcap_files, key=os.path.getctime)
                self.logger.debug(f"Found latest PCAP file: {latest}")
                return latest
            except Exception as e:
                self.logger.debug(f"Error finding PCAP files: {str(e)}")
                return None

        # Wait for PCAP files to be available
        max_retries = 30
        retry_count = 0
        path = None

        while retry_count < max_retries:
            path = get_latest_pcap()
            if path:
                break
            self.logger.debug(f"Waiting for PCAP files... (attempt {retry_count + 1}/{max_retries})")
            time.sleep(2)
            retry_count += 1

        if not path:
            self.logger.debug(f"No PCAP files found after {max_retries} attempts. Exiting.")
            sys.exit(1)

        # Initialize Kitsune with custom learning rate for robustness
        try:
            self.kitsune = Kitsune(path, self.packet_limit, self.maxAE, self.FMgrace, self.ADgrace, learning_rate=self.learning_rate, hidden_ratio=self.hidden_ratio)
        except Exception as e:
            self.logger.debug(f"Failed to initialize Kitsune: {str(e)}")
            sys.exit(1)

        self.current_file = path
        self.last_processed_size = 0

    def setup_logging(self):
        self.logger = logging.getLogger('kitsune')
        self.logger.setLevel(logging.INFO)
        log_dir = "/app/logs/kitsune"
        os.makedirs(log_dir, exist_ok=True)
        handler = logging.FileHandler(os.path.join(log_dir, 'anomaly.log'))
        handler.setFormatter(JsonFormatter())
        self.logger.addHandler(handler)

    def handle_shutdown(self, signum, frame):
        self.logger.info("Received shutdown signal, cleaning up...")
        self.running = False

    def initialize_kitsune(self):
        self.logger.info(f"Initializing Kitsune with parameters: maxAE={self.maxAE}, FMgrace={self.FMgrace}, ADgrace={self.ADgrace}")
        self.kitsune = Kitsune(
            self.current_file,
            self.packet_limit,
            self.maxAE,
            self.FMgrace,
            self.ADgrace,
            learning_rate=self.learning_rate,
            hidden_ratio=self.hidden_ratio
        )

    def process_packets(self):
        packet_count = 0
        start_time = time.time()

        while self.running:
            if not os.path.exists(self.current_file):
                time.sleep(1)
                continue

            current_size = os.path.getsize(self.current_file)
            if current_size == self.last_processed_size:
                time.sleep(1)
                continue
            if self.kitsune is None:
                self.initialize_kitsune()

            try:
                while True:
                    try:
                        packet_count += 1
                        if packet_count % 1000 == 0:
                            self.logger.debug(f"Processed {packet_count} packets")
                        
                        # Process the next packet and get RMSE
                        rmse = self.kitsune.proc_next_packet()
                        if rmse == -1:  # End of PCAP file
                            # Try to get next PCAP file
                            path = get_latest_pcap()
                            if path and path != self.kitsune.FE.path:
                                self.logger.debug(f"Switching to new PCAP file: {path}")
                                self.kitsune = Kitsune(path, self.packet_limit, self.maxAE, self.FMgrace, self.ADgrace, learning_rate=self.learning_rate, hidden_ratio=self.hidden_ratio)
                                continue
                            break
                        if rmse > self.anomaly_threshold:
                            self.logger.info(json.dumps({
                                'packet_id': packet_count,
                                'rmse': float(rmse),
                                'anomaly': True,
                                'timestamp': datetime.now().isoformat()
                            }))
                    except Exception as e:
                        self.logger.error(f"Error processing packet: {str(e)}")
                        time.sleep(1)
            except Exception as e:
                self.logger.error(f"Error processing packet: {str(e)}")
                time.sleep(1)

            self.last_processed_size = current_size

    def run(self):
        self.logger.info("Starting Kitsune monitoring service")
        try:
            self.process_packets()
        except Exception as e:
            self.logger.error(f"Fatal error: {str(e)}")
        finally:
            self.logger.info("Kitsune monitoring service stopped")

if __name__ == "__main__":
    monitor = KitsuneMonitor()
    monitor.run()
