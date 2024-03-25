import argparse
import ipaddress
import socket
import time
from packet import Packet
from ordered_set import OrderedSet
import threading
from send_receive_utility import send_data_thread, monitor_for_timeout, receive_ack_thread
from send_receive_utility import AckQueue
from send_receive_utility import ReceiverBuffer
from send_receive_utility import get_timeout

# Initialize variables
data_packets = set()
conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ack_queue = AckQueue()
sent_packets = {}
last_data_seq_number_sent = -1


# Function to handle response received from server
def handle_response(conn, data, sender, receiver_buffer):
    try:
        packet = Packet.from_bytes(data)
        if packet.is_data():
            print(f'Received Data packet with SeqNum={packet.seq_num} from {sender}')

            receiver_buffer.insert_packet(packet)
            if data_packet_number == 1:
                receiver_buffer.get_content_length
            ack_packet = Packet(packet_type=Packet.DATA_ACK,
                                seq_num=packet.seq_num + 1,
                                peer_addr=packet.get_peer_ip_addr(),
                                peer_port=packet.get_peer_port(),
                                payload=b"")
            conn.sendto(ack_packet.to_bytes(), sender)
            print(f'Sent Data-ACK with SeqNum={ack_packet.seq_num + 1} to {sender}')
            data_packets.add(packet.seq_num)

    except Exception as e:
        print("Error: ", e)


# Variable to control monitoring thread
stop_monitoring = False


# Function to check for SYN timeout
def check_for_syn_timeout(timeout, seq_num, peer_ip, server_port, router_addr, router_port, timestamp):
    global stop_monitoring
    while True:
        if time.time() - timestamp > timeout:
            if (stop_monitoring):
                break
            syn_packet = Packet(packet_type=Packet.SYN,
                                seq_num=seq_num,
                                peer_addr=peer_ip,
                                peer_port=server_port,
                                payload=b"")
            conn.sendto(syn_packet.to_bytes(), (router_addr, router_port))
            timestamp = time.time()
            print(f'Sent SYN with SeqNum={syn_packet.seq_num} to router')


# Function to run the client
def run_client(router_addr, router_port, server_addr, server_port, file_path, verbose, output):
    # Convert server address to IP address
    peer_ip = ipaddress.ip_address(socket.gethostbyname(server_addr))
    global conn, last_data_seq_number_sent, stop_monitoring
    timeout = get_timeout()
    window_size = 5
    seq_num = 1

    start_time = time.time()

    try:
        # Send SYN packet to initiate connection
        syn_packet = Packet(packet_type=Packet.SYN,
                            seq_num=seq_num,
                            peer_addr=peer_ip,
                            peer_port=server_port,
                            payload=b"")
        conn.sendto(syn_packet.to_bytes(), (router_addr, router_port))
        timestamp = time.time()
        print(f'Sent SYN with SeqNum={syn_packet.seq_num} to router')
        # Start monitoring for SYN timeout
        monitor_thread = threading.Thread(target=check_for_syn_timeout, args=(
        timeout, seq_num, peer_ip, server_port, router_addr, router_port, timestamp))
        monitor_thread.start()

        # Receive SYN-ACK response from server
        while True:
            syn_ack_response, sender = conn.recvfrom(1024)
            syn_ack_packet = Packet.from_bytes(syn_ack_response)
            ack_queue.received_acks.add(1)
            print(f'Received SYN-ACK with SeqNum={syn_ack_packet.seq_num} from {sender}')
            ack_queue.received_acks.add(2)
            if syn_ack_packet.is_syn_ack():
                stop_monitoring = True
                break
            if not syn_ack_packet.is_syn_ack():
                print("Invalid SYN-ACK packet received. Trying again.")
        seq_num += 1

        # Start threads for monitoring, sending data, and receiving acknowledgments
        monitor_thread = threading.Thread(target=monitor_for_timeout, args=(
        router_addr, router_port, timeout, conn, ack_queue, sent_packets, last_data_seq_number_sent))
        time.sleep(0.5)
        send_thread = threading.Thread(target=send_data_thread, args=(
        file_path, router_addr, router_port, peer_ip, server_port, window_size, conn, ack_queue, sent_packets,
        last_data_seq_number_sent))
        receive_thread = threading.Thread(target=receive_ack_thread, args=(
        conn, ack_queue, sent_packets, last_data_seq_number_sent, "post", verbose, output))
        monitor_thread.start()
        send_thread.start()
        receive_thread.start()
        monitor_thread.join()
        send_thread.join()
        receive_thread.join()
        print("File transfer completed successfully.")

    except socket.timeout:
        print('No response after {}s'.format(timeout))
    finally:
        end_time = time.time()
        print(f"Total time taken: {end_time - start_time} seconds")
        conn.close()


if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--routerhost", help="router host", default="localhost")
    parser.add_argument("--routerport", help="router port", type=int, default=3000)
    parser.add_argument("--serverhost", help="server host", default="localhost")
    parser.add_argument("--serverport", help="server port", type=int, default=8007)
    parser.add_argument("--file", help="file path for transfer", required=True)
    args = parser.parse_args()

    # Run the client with provided arguments
    run_client(args.routerhost, args.routerport, args.serverhost, args.serverport, args.file)
