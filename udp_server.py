import argparse
import socket
from packet import Packet
import socket
import threading
import argparse
import udp_server
from file_server_application import handle_get_request, handle_post_request
from send_receive_utility import send_data_thread, monitor_for_timeout, receive_ack_thread
from send_receive_utility import AckQueue
from send_receive_utility import ReceiverBuffer
from send_receive_utility import get_timeout
import time

data_packets = set()
data_in_data_packets = set()

ack_queue = AckQueue()
sent_packets = {}
conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
last_data_seq_number_sent = -1
file_lock = threading.Lock()
lock_status = False
terminate = False
def parse_http_request(request):
    try:
        request_lines = request.split('\r\n')
        method, path, _ = request_lines[0].split(' ')

        body = request_lines[-1]
        return method, path, body
    except:
        return None, None, None

terminate_server = False
def run_server(port, data_dir):
    global data_packets
    global terminate_server
    
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        conn.bind(('', port))
        print('Server is listening at', port)

        receiver_buffer = ReceiverBuffer(data_packets)

        while True:
            data, sender = conn.recvfrom(1024)
            
            handle_client(conn, data, sender, receiver_buffer, data_dir)
            if terminate_server:
                break
    finally:
        conn.close()
        
stop_monitoring = False

def handle_client(conn, data, sender, receiver_buffer, data_dir):
    global data_packets
    global lock_status
    global data_in_data_packets
    timeout = get_timeout()
   
    global  terminate_server
    #try:
    packet = Packet.from_bytes(data)

    if packet.is_syn():
        # Handle SYN packet
        print(f'Received SYN from {sender}')
        syn_ack_packet = Packet(packet_type=Packet.SYN_ACK,
                                seq_num=packet.seq_num + 1,
                                peer_addr=packet.get_peer_ip_addr(),
                                peer_port=packet.get_peer_port(),
                                payload=b"")
        conn.sendto(syn_ack_packet.to_bytes(), sender)
        print(f'Sent SYN-ACK with SeqNum={syn_ack_packet.seq_num} to {sender}')
        data_packets.add(packet.seq_num)
    elif packet.is_data():
        # Handle Data packet
        print(f'Received Data packet with SeqNum={packet.seq_num} from {sender}')

        receiver_buffer.insert_packet(packet)

        # Acknowledge the received Data packet
        ack_packet = Packet(packet_type=Packet.DATA_ACK,
                            seq_num=packet.seq_num + 1,
                            peer_addr=packet.get_peer_ip_addr(),
                            peer_port=packet.get_peer_port(),
                            payload=b"")
        conn.sendto(ack_packet.to_bytes(), sender)
        print(f'Sent Data-ACK with SeqNum={ack_packet.seq_num} to {sender}')
        data_packets.add(packet.seq_num)
        data_in_data_packets.add(packet.payload.decode('utf-8'))

        c = 0
        c2 = 0
        for i in data_in_data_packets:
            if '\r\r\n\r\r\n' in i:
                c += len(i.split('\r\r\n\r\r\n')[1])
            else:
                c += len(i)
        print(data_packets)
        method, path, body = parse_http_request(receiver_buffer.prints())
        if method is not None and method == "GET":
            if not lock_status and file_lock.acquire(blocking=False):
                timeout = get_timeout()
                router_host, router_port = sender
                lock_status = True
                response = handle_get_request(data_dir, path)
                f = open("get.txt", 'wb')
                f.write(response)
                f.close()
                file_path = "get.txt"
                router_addr = router_host
                global terminate
                monitor_thread = threading.Thread(target=monitor_for_timeout,
                                                  args=(
                                                  router_addr, router_port, timeout, conn, ack_queue, sent_packets,
                                                  last_data_seq_number_sent))
                time.sleep(0.5)
                send_thread = threading.Thread(target=send_data_thread, args=(
                    file_path, router_addr, router_port, packet.get_peer_ip_addr(), packet.get_peer_port(),
                    window_size := 5, conn, ack_queue, sent_packets, last_data_seq_number_sent, seq_num := 2))
                receive_thread = threading.Thread(target=receive_ack_thread,
                                                  args=(conn, ack_queue, sent_packets, last_data_seq_number_sent))
                monitor_thread.start()
                send_thread.start()
                receive_thread.start()
                monitor_thread.join()
                send_thread.join()
                receive_thread.join()
                terminate_server = 1
        if receiver_buffer.get_content_length() == c:
            method, path, body = parse_http_request(receiver_buffer.prints())

            if method == "POST":

                if not lock_status and file_lock.acquire(blocking=False):
                    lock_status = True

                    response = handle_post_request(data_dir, path, body)

                    time.sleep(0.5)
                    data_packet = Packet(packet_type=Packet.DATA,
                                         seq_num=1,
                                         peer_addr=packet.get_peer_ip_addr(),
                                         peer_port=packet.get_peer_port(),
                                         payload=response)
                    router_addr, router_port = sender
                    conn.sendto(data_packet.to_bytes(), (router_addr, router_port))
                    timestamp = time.time()
                    print(f'Sent Response Packet(DATA PACKET) with SeqNum={1} to router')
                    conn.settimeout(timeout)
                    while True:
                        if time.time() - timestamp > timeout:
                            response_packet = Packet(packet_type=Packet.DATA,
                                                     seq_num=1,
                                                     peer_addr=packet.get_peer_ip_addr(),
                                                     peer_port=packet.get_peer_port(),
                                                     payload=response)
                            conn.sendto(response_packet.to_bytes(), (router_addr, router_port))
                            timestamp = time.time()
                            print(f'Sent Response Packet(DATA PACKET) with SeqNum={1} to router')

                        try:
                            ack_response, sender = conn.recvfrom(1024)
                            ack_packet = Packet.from_bytes(ack_response)
                            ack_queue.received_acks.add(1)
                            print(f'Received ACK for response with SeqNum={ack_packet.seq_num} from {sender}')

                            if ack_packet.is_data_ack():
                                #print("ACK received")
                                break

                            if not ack_packet.is_data_ack():
                                print("Invalid ACK packet received. Trying again.")

                        except socket.timeout:
                            # Handle timeout: Resend response packet or take appropriate action
                            response_packet = Packet(packet_type=Packet.DATA,
                                                     seq_num=1,
                                                     peer_addr=packet.get_peer_ip_addr(),
                                                     peer_port=packet.get_peer_port(),
                                                     payload=response)
                            conn.sendto(response_packet.to_bytes(), (router_addr, router_port))
                            timestamp = time.time()
                            print(f'Resent Response Packet(DATA PACKET) with SeqNum={1} to router')

                    # Reset the socket timeout to None or an appropriate value
                    conn.settimeout(None)


                    fin_packet = Packet(packet_type=Packet.FIN,
                                        seq_num=2,
                                        peer_addr=packet.get_peer_ip_addr(),
                                        peer_port=packet.get_peer_port(),
                                        payload=b"")
                    conn.sendto(fin_packet.to_bytes(), sender)
                    timestamp = time.time()
                    print(f'Sent FIN with SeqNum={fin_packet.seq_num} to router')
                    #conn.close()
                    conn.settimeout(timeout)
                    counter = 0
                    while True:
                        try:
                            ack_response, sender = conn.recvfrom(1024)
                            ack_packet = Packet.from_bytes(ack_response)

                            if ack_packet.is_fin_ack():
                                print(f'Received FIN ACK with SeqNum={ack_packet.seq_num} from {sender}')
                                # Stop the loop if FIN ACK is received
                                break

                            # If an unexpected packet is received, print a message and continue the loop
                            print("Unexpected packet received. Trying again.")

                        except socket.timeout:
                            # Handle timeout: Resend FIN packet or take appropriate action
                            fin_packet = Packet(packet_type=Packet.FIN,
                                                seq_num=2,
                                                peer_addr=packet.get_peer_ip_addr(),
                                                peer_port=packet.get_peer_port(),
                                                payload=b"")
                            conn.sendto(fin_packet.to_bytes(), sender)
                            print(f'Sent FIN with SeqNum={fin_packet.seq_num} to router')

                            # Update the timestamp to track the new timeout period
                            timestamp = time.time()
                            counter += 1
                            if(counter == 5):
                                print(f'Received FIN ACK with SeqNum={fin_packet.seq_num} from {sender}')
                                exit(0)
                    # Reset the socket timeout to None or an appropriate value
                    conn.settimeout(None)

                    terminate_server = 1
                    #monitor_thread.join()

                else:
                    response = "HTTP/1.0 503 Service Unavailable\r\n\r\nLock is held by another process.".encode()

            else:
                response = "HTTP/1.0 405 Method Not Allowed\r\n\r\nMethod not allowed.".encode()
    elif packet.is_fin():
        # Handle FIN packet
        print(f'Received FIN from {sender}')
        fin_ack_packet = Packet(packet_type=Packet.FIN_ACK,
                                seq_num=packet.seq_num + 1,
                                peer_addr=packet.get_peer_ip_addr(),
                                peer_port=packet.get_peer_port(),
                                payload=b"")
        conn.sendto(fin_ack_packet.to_bytes(), sender)
        print(f'Sent FIN-ACK with SeqNum={fin_ack_packet.seq_num + 1} to {sender}')
        
        data_packets.add(packet.seq_num)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", help="server port", type=int, default=8007)
    args = parser.parse_args()
    run_server(args.port)
