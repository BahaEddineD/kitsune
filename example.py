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

        # Kitsune parameters
        self.packet_limit = np.Inf
        self.maxAE = 10
        self.FMgrace = 5000
        self.ADgrace = 50000
        self.learning_rate = 0.01
        self.hidden_ratio = 0.75
        self.anomaly_threshold = 0.1

        # File monitoring
        self.pcap_dir = "/data"
        self.current_file = os.path.join(self.pcap_dir, "current.pcap")
        self.last_processed_size = 0
        self.kitsune = None

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
                rmse = self.kitsune.proc_next_packet()
                if rmse == -1:
                    self.logger.info("End of file reached, waiting for new data...")
                    self.kitsune = None
                    time.sleep(1)
                    continue

                packet_count += 1
                if packet_count % 1000 == 0:
                    self.logger.info(f"Processed {packet_count} packets")

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
