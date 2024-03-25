import ipaddress

class Packet:
    # Define packet type constants
    SYN = 1
    SYN_ACK = 2
    FIN = 4
    FIN_ACK = 5
    DATA = 6
    DATA_ACK = 7

    def __init__(self, packet_type, seq_num, peer_addr, peer_port, payload):
        # Initialize packet attributes
        self.packet_type = int(packet_type)  # Packet type
        self.seq_num = int(seq_num)  # Sequence number
        self.peer_ip_addr = ipaddress.ip_address(peer_addr)  # Peer IP address
        self.peer_port = int(peer_port)  # Peer port
        self.payload = payload  # Payload data

    def to_bytes(self):
        # Convert packet attributes to bytes
        buf = bytearray()
        buf.extend(self.packet_type.to_bytes(1, byteorder='big'))  # Packet type
        buf.extend(self.seq_num.to_bytes(4, byteorder='big'))  # Sequence number
        buf.extend(self.peer_ip_addr.packed)  # Peer IP address
        buf.extend(self.peer_port.to_bytes(2, byteorder='big'))  # Peer port
        buf.extend(self.payload)  # Payload data
        return buf

    def get_peer_ip_addr(self):
        # Get peer IP address
        return self.peer_ip_addr

    def get_peer_port(self):
        # Get peer port
        return str(self.peer_port)

    @staticmethod
    def from_bytes(raw):
        # Construct Packet object from bytes
        try:
            if len(raw) < 11:
                raise ValueError("Packet is too short")
            packet_type = int.from_bytes(raw[0:1], byteorder='big')  # Extract packet type
            seq_num = int.from_bytes(raw[1:5], byteorder='big')  # Extract sequence number
            peer_addr = ipaddress.ip_address(raw[5:9])  # Extract peer IP address
            peer_port = int.from_bytes(raw[9:11], byteorder='big')  # Extract peer port
            payload = raw[11:]  # Extract payload data
            return Packet(packet_type=packet_type,
                          seq_num=seq_num,
                          peer_addr=peer_addr,
                          peer_port=peer_port,
                          payload=payload)
        except Exception as e:
            print(f"Error in from_bytes: {e}")

    # Methods to check packet types
    def is_syn(self):
        return self.packet_type == self.SYN

    def is_syn_ack(self):
        return self.packet_type == self.SYN_ACK

    def is_data(self):
        return self.packet_type == self.DATA

    def is_data_ack(self):
        return self.packet_type == self.DATA_ACK

    def is_fin(self):
        return self.packet_type == self.FIN

    def is_fin_ack(self):
        return self.packet_type == self.FIN_ACK

    def is_ack(self):
        # Check if packet is an acknowledgment packet
        return self.packet_type in [self.DATA_ACK, self.SYN_ACK, self.FIN_ACK]

    # Additional method
    def is_fin_ack_ack(self):
        return self.packet_type == self.FIN_ACK_ACK

    def __repr__(self, *args, **kwargs):
        # String representation of Packet object
        return f"SeqNum={self.seq_num}, peer={self.peer_ip_addr}:{self.peer_port}, type={self.packet_type}, size={len(self.payload)}"
