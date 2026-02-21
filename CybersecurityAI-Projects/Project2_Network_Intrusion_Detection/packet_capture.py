"""
Network Packet Capture Module
Captures and processes network packets for intrusion detection
"""

from fileinput import filename
from fileinput import filename
import socket
import struct
import time
from collections import defaultdict
from datetime import datetime
import threading
import json
import numpy as np
import json
import numpy as np

import json
import numpy as np

def convert_numpy_types(obj):
    """Recursively convert numpy types in dict/list to native Python types."""
    if isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(i) for i in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_numpy_types(i) for i in obj)
    elif isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float32, np.float64)):
        return float(obj)
    elif isinstance(obj, np.bool_):
        return bool(obj)
    else:
        return obj

def save_packets(self, filepath="packets.json"):
    """Save captured packets to a JSON file safely handling numpy types."""
    serializable_packets = convert_numpy_types(self.packets)
    with open(filepath, "w") as f:
        json.dump(serializable_packets, f, indent=2)
    print(f"Packets saved to {filepath}")


class PacketCapture:
    def __init__(self, interface=None, timeout=60):
        self.interface = interface
        self.timeout = timeout
        self.running = False
        self.packets = []
        self.flows = defaultdict(lambda: {
            'packets': [],
            'bytes': [],
            'timestamps': [],
            'flags': []
        })
        self.lock = threading.Lock()
        self.capture_thread = None
        
    def parse_ip_header(self, data):
        """Parse IP header from raw packet data"""
        try:
            version_ihl = data[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0x0F
            
            if version != 4:
                return None
                
            tos = data[1]
            total_length = struct.unpack('!H', data[2:4])[0]
            identification = struct.unpack('!H', data[4:6])[0]
            flags_offset = struct.unpack('!H', data[6:8])[0]
            ttl = data[8]
            protocol = data[9]
            header_checksum = struct.unpack('!H', data[10:12])[0]
            src_addr = socket.inet_ntoa(data[12:16])
            dst_addr = socket.inet_ntoa(data[16:20])
            
            header_length = ihl * 4
            
            return {
                'version': version,
                'tos': tos,
                'total_length': total_length,
                'identification': identification,
                'ttl': ttl,
                'protocol': protocol,
                'src_addr': src_addr,
                'dst_addr': dst_addr,
                'header_length': header_length
            }
        except Exception as e:
            return None
    
    def parse_tcp_header(self, data):
        """Parse TCP header from packet data"""
        try:
            src_port = struct.unpack('!H', data[0:2])[0]
            dst_port = struct.unpack('!H', data[2:4])[0]
            sequence_number = struct.unpack('!I', data[4:8])[0]
            ack_number = struct.unpack('!I', data[8:12])[0]
            data_offset_flags = struct.unpack('!H', data[12:14])[0]
            data_offset = (data_offset_flags >> 12) * 4
            flags = data_offset_flags & 0x3F
            window = struct.unpack('!H', data[14:16])[0]
            checksum = struct.unpack('!H', data[16:18])[0]
            urgent_pointer = struct.unpack('!H', data[18:20])[0]
            
            return {
                'src_port': src_port,
                'dst_port': dst_port,
                'sequence_number': sequence_number,
                'ack_number': ack_number,
                'flags': flags,
                'window': window,
                'checksum': checksum,
                'urgent_pointer': urgent_pointer
            }
        except Exception as e:
            return None
    
    def parse_udp_header(self, data):
        """Parse UDP header from packet data"""
        try:
            src_port = struct.unpack('!H', data[0:2])[0]
            dst_port = struct.unpack('!H', data[2:4])[0]
            length = struct.unpack('!H', data[4:6])[0]
            checksum = struct.unpack('!H', data[6:8])[0]
            
            return {
                'src_port': src_port,
                'dst_port': dst_port,
                'length': length,
                'checksum': checksum
            }
        except Exception as e:
            return None
    
    def get_protocol_name(self, protocol_num):
        """Get protocol name from number"""
        protocols = {
            1: 'icmp',
            6: 'tcp',
            17: 'udp'
        }
        return protocols.get(protocol_num, 'other')
    
    def get_tcp_flags(self, flags):
        """Get TCP flag names"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return flag_names
    
    def packet_to_features(self, packet_info):
        """Convert packet information to features for ML model"""
        features = {}
        
        # Protocol type
        protocol_map = {'tcp': 1, 'udp': 2, 'icmp': 3, 'other': 4}
        features['protocol_type'] = protocol_map.get(
            packet_info.get('protocol', 'other'), 4
        )
        
        # Service (based on port)
        port = packet_info.get('dst_port', 0)
        if port == 80 or port == 8080:
            features['service'] = 1  # http
        elif port == 443:
            features['service'] = 2  # https
        elif port == 21:
            features['service'] = 3  # ftp
        elif port == 22:
            features['service'] = 4  # ssh
        elif port == 25:
            features['service'] = 5  # smtp
        elif port == 53:
            features['service'] = 6  # dns
        else:
            features['service'] = 7  # other
        
        # Flag (TCP flags)
        flags = packet_info.get('tcp_flags', [])
        if 'SYN' in flags and 'ACK' not in flags:
            features['flag'] = 1  # S0
        elif 'SYN' in flags and 'ACK' in flags:
            features['flag'] = 2  # SF
        elif 'RST' in flags:
            features['flag'] = 3  # REJ
        elif 'FIN' in flags:
            features['flag'] = 4  # SF
        elif 'PSH' in flags and 'ACK' in flags:
            features['flag'] = 5  # SF
        else:
            features['flag'] = 6  # SF
        
        # Bytes
        features['src_bytes'] = packet_info.get('packet_size', 0)
        features['dst_bytes'] = 0
        features['src_packets'] = 1
        features['dst_packets'] = 0
        
        # Error rates (simulated)
        features['serror_rate'] = 0.0
        features['rerror_rate'] = 0.0
        features['same_srv_rate'] = 0.5
        features['diff_srv_rate'] = 0.5
        
        # Connection counts
        features['count'] = 1
        features['srv_count'] = 1
        features['serror_count'] = 1 if 'RST' in flags else 0
        features['rerror_count'] = 0
        
        # Duration
        features['duration'] = 0
        
        # Attack indicators
        features['land'] = 0
        features['wrong_fragment'] = 0
        features['urgent'] = 1 if 'URG' in flags else 0
        features['hot'] = 0
        features['num_failed_logins'] = 0
        features['logged_in'] = 1 if 'ACK' in flags else 0
        features['num_compromised'] = 0
        features['su_attempted'] = 0
        features['num_root'] = 0
        features['num_file_creations'] = 0
        features['num_shells'] = 0
        features['num_access_files'] = 0
        features['is_guest_login'] = 0
        
        return features
    
    def capture_packets(self, count=100):
        """Capture network packets (simulated)"""
        print(f"Capturing {count} packets...")
        
        # Simulate packet capture
        for i in range(count):
            packet_info = self._generate_simulated_packet(i)
            with self.lock:
                self.packets.append(packet_info)
            
            if i % 10 == 0:
                print(f"Captured {i + 1}/{count} packets")
            
            time.sleep(0.01)  # Small delay between packets
        
        print(f"Captured {len(self.packets)} packets total")
        return self.packets
    
    def _generate_simulated_packet(self, index):
        """Generate a simulated packet for testing"""
        np.random.seed(index)
        
        protocols = ['tcp', 'udp', 'icmp']
        protocol = np.random.choice(protocols, p=[0.7, 0.25, 0.05])
        
        src_ports = [80, 443, 22, 25, 53, 8080, 21, 3306, 8080, 3000]
        dst_ports = [np.random.randint(1024, 65535) for _ in range(10)]
        
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'protocol': protocol,
            'src_addr': f"192.168.1.{np.random.randint(1, 255)}",
            'dst_addr': f"192.168.1.{np.random.randint(1, 255)}",
            'src_port': np.random.choice(src_ports),
            'dst_port': np.random.choice(dst_ports),
            'packet_size': np.random.randint(64, 1500),
            'tcp_flags': self._generate_random_flags()
        }
        
        return packet_info
    
    def _generate_random_flags(self):
        """Generate random TCP flags"""
        flags = []
        if np.random.random() < 0.3:
            flags.append('SYN')
        if np.random.random() < 0.2:
            flags.append('ACK')
        if np.random.random() < 0.05:
            flags.append('RST')
        if np.random.random() < 0.1:
            flags.append('FIN')
        if np.random.random() < 0.15:
            flags.append('PSH')
        if np.random.random() < 0.02:
            flags.append('URG')
        return flags if flags else ['PSH', 'ACK']
    
    def build_flows(self):
        """Build network flows from captured packets"""
        print("Building network flows...")
        
        for packet in self.packets:
            flow_key = (
                packet['src_addr'],
                packet['dst_addr'],
                packet['protocol'],
                packet['src_port'],
                packet['dst_port']
            )
            
            self.flows[flow_key]['packets'].append(packet)
            self.flows[flow_key]['bytes'].append(packet['packet_size'])
            self.flows[flow_key]['timestamps'].append(packet['timestamp'])
            self.flows[flow_key]['flags'].extend(packet.get('tcp_flags', []))
        
        print(f"Built {len(self.flows)} network flows")
        return self.flows
    
    def extract_flow_features(self, flow_key, flow_data):
        """Extract features from a network flow"""
        packets = flow_data['packets']
        bytes_list = flow_data['bytes']
        timestamps = flow_data['timestamps']
        flags = flow_data['flags']
        
        if not packets:
            return None
        
        # Calculate duration
        if len(timestamps) > 1:
            start_time = datetime.fromisoformat(timestamps[0])
            end_time = datetime.fromisoformat(timestamps[-1])
            duration = (end_time - start_time).total_seconds()
        else:
            duration = 0.01
        
        # Protocol type
        protocol_map = {'tcp': 1, 'udp': 2, 'icmp': 3}
        protocol_type = protocol_map.get(packets[0]['protocol'], 4)
        
        # Service (based on destination port)
        dst_port = packets[0]['dst_port']
        if dst_port == 80 or dst_port == 8080:
            service = 1
        elif dst_port == 443:
            service = 2
        elif dst_port == 21:
            service = 3
        elif dst_port == 22:
            service = 4
        elif dst_port == 25:
            service = 5
        elif dst_port == 53:
            service = 6
        else:
            service = 7
        
        # Flag (most common)
        flag_counts = {}
        for f in flags:
            flag_counts[f] = flag_counts.get(f, 0) + 1
        most_common_flag = max(flag_counts, key=flag_counts.get) if flag_counts else 'PSH'
        
        flag_map = {
            'SYN': 1, 'RST': 3, 'FIN': 4, 'PSH': 6, 'ACK': 6, 'URG': 7
        }
        flag = flag_map.get(most_common_flag, 6)
        
        # Bytes and packets
        src_bytes = sum(bytes_list)
        dst_bytes = 0
        src_packets = len(packets)
        dst_packets = 0
        
        # Error rates
        serror_count = flags.count('RST')
        serror_rate = serror_count / len(flags) if flags else 0
        rerror_rate = 0
        
        # Same/diff service rates
        same_srv_rate = 0.7
        diff_srv_rate = 0.3
        
        # Connection counts
        count = len(packets)
        srv_count = len(packets)
        
        # Land attack check
        land = 1 if packets[0]['src_addr'] == packets[0]['dst_addr'] else 0
        
        return {
            'duration': duration,
            'protocol_type': protocol_type,
            'service': service,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'src_packets': src_packets,
            'dst_packets': dst_packets,
            'serror_rate': serror_rate,
            'rerror_rate': rerror_rate,
            'same_srv_rate': same_srv_rate,
            'diff_srv_rate': diff_srv_rate,
            'count': count,
            'srv_count': srv_count,
            'serror_count': serror_count,
            'rerror_count': 0,
            'land': land,
            'wrong_fragment': 0,
            'urgent': flags.count('URG'),
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 1 if 'ACK' in flags else 0,
            'num_compromised': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'is_guest_login': 0
        }
    
    def get_all_flow_features(self):
        """Get features for all flows"""
        all_features = []
        
        for flow_key, flow_data in self.flows.items():
            features = self.extract_flow_features(flow_key, flow_data)
            if features:
                all_features.append(features)
        
        return all_features
    
    def save_packets(self, filename='captured_packets.json'):
        """Save captured packets to file safely handling numpy types"""
        serializable_packets = convert_numpy_types(self.packets)
        with open(filename, 'w') as f:
            json.dump(serializable_packets, f, indent=2)
        print(f"Packets saved to {filename}")


def main():
    """Main function to demonstrate packet capture"""
    print("="*60)
    print("NETWORK PACKET CAPTURE MODULE")
    print("="*60)
    
    # Initialize packet capture
    capture = PacketCapture()
    
    # Capture packets
    packets = capture.capture_packets(count=50)
    
    # Build flows
    capture.build_flows()
    
    # Get flow features
    flow_features = capture.get_all_flow_features()
    print(f"\nExtracted features for {len(flow_features)} flows")
    
    # Save packets
    capture.save_packets()
    
    # Display sample packet
    print("\n" + "="*60)
    print("SAMPLE CAPTURED PACKET")
    print("="*60)
    if packets:
        sample = packets[0]
        print(f"Protocol: {sample['protocol']}")
        print(f"Source: {sample['src_addr']}:{sample['src_port']}")
        print(f"Destination: {sample['dst_addr']}:{sample['dst_port']}")
        print(f"Size: {sample['packet_size']} bytes")
        print(f"Flags: {', '.join(sample['tcp_flags'])}")
    
    print("\n" + "="*60)
    print("PACKET CAPTURE COMPLETE!")
    print("="*60)


if __name__ == "__main__":
    main()