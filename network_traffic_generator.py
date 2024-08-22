import socket
import random
import time
import threading
import ipaddress
import csv
from collections import defaultdict

# Configuration
CONFIG = {
    'source_subnets': ['192.168.1.0/24', '172.16.0.0/16'],  # List of source subnets
    'dest_subnets': ['10.0.0.0/24', '192.168.2.0/24'],     # List of destination subnets
    'ports': [80, 443, 22, 3306, 5432, 8080],              # List of ports to use
    'min_delay': 0.5,                                      # Minimum delay between requests (seconds)
    'max_delay': 2.0,                                      # Maximum delay between requests (seconds)
    'duration': None,                                      # Duration to run (seconds), None for indefinite
    'patterns_file': None                                  # CSV file with traffic patterns (optional)
}

class TrafficGenerator:
    def __init__(self, config):
        self.config = config
        self.traffic_patterns = self.load_traffic_patterns()
        self.stop_event = threading.Event()

    def load_traffic_patterns(self):
        patterns = defaultdict(list)
        if self.config['patterns_file']:
            with open(self.config['patterns_file'], 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    patterns[row['source_subnet']].append({
                        'dest_subnet': row['dest_subnet'],
                        'port': int(row['port']),
                        'protocol': row['protocol'],
                        'weight': int(row['weight'])
                    })
        return patterns

    def generate_ip_from_subnet(self, subnet):
        network = ipaddress.ip_network(subnet)
        return str(random.choice(list(network.hosts())))

    def generate_traffic(self, source, destination, port, protocol):
        try:
            if protocol == 'TCP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((destination, port))
                message = f"Test TCP traffic from {source} to {destination} on port {port}"
                sock.sendall(message.encode())
                sock.close()
            elif protocol == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                message = f"Test UDP traffic from {source} to {destination} on port {port}"
                sock.sendto(message.encode(), (destination, port))
            print(f"Sent: {protocol} {message}")
        except Exception as e:
            print(f"Error sending {protocol} traffic from {source} to {destination}:{port} - {str(e)}")

    def traffic_generator(self):
        start_time = time.time()
        while not self.stop_event.is_set():
            if self.config['duration'] and (time.time() - start_time) > self.config['duration']:
                break
            
            if self.traffic_patterns:
                source_subnet = random.choice(list(self.traffic_patterns.keys()))
                pattern = random.choices(self.traffic_patterns[source_subnet], 
                                         weights=[p['weight'] for p in self.traffic_patterns[source_subnet]])[0]
                source = self.generate_ip_from_subnet(source_subnet)
                destination = self.generate_ip_from_subnet(pattern['dest_subnet'])
                port = pattern['port']
                protocol = pattern['protocol']
            else:
                source = self.generate_ip_from_subnet(random.choice(self.config['source_subnets']))
                destination = self.generate_ip_from_subnet(random.choice(self.config['dest_subnets']))
                port = random.choice(self.config['ports'])
                protocol = random.choice(['TCP', 'UDP'])
            
            thread = threading.Thread(target=self.generate_traffic, args=(source, destination, port, protocol))
            thread.start()
            
            time.sleep(random.uniform(self.config['min_delay'], self.config['max_delay']))

    def run(self):
        duration_msg = 'unlimited time' if self.config['duration'] is None else f"{self.config['duration']} seconds"
        print(f"Starting network traffic generation for {duration_msg}...")
        print(f"Source subnets: {', '.join(self.config['source_subnets'])}")
        print(f"Destination subnets: {', '.join(self.config['dest_subnets'])}")
        print(f"Ports: {', '.join(map(str, self.config['ports']))}")
        self.traffic_generator()
        print("Traffic generation completed.")

if __name__ == "__main__":
    generator = TrafficGenerator(CONFIG)
    try:
        generator.run()
    except KeyboardInterrupt:
        print("\nTraffic generation interrupted by user.")
    finally:
        generator.stop_event.set()
