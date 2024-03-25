from packet import Packet
import time

class AckQueue:
    def __init__(self):
        self.received_acks = set()
        self.max_ack = 0

    def put(self, seq_num):
        self.received_acks.add(seq_num)
        self.max_ack = max(self.received_acks)

    def acknowledge(self, seq_num):
        self.received_acks.add(seq_num)

    def get_send_base(self):
        sorted_oset = sorted(self.received_acks)

        for i, element in enumerate(sorted_oset, start=1):
            if i != element:
                return i

        return len(sorted_oset) + 1

class ReceiverBuffer:

    def __init__(self, data_packets):
        self.buffer = set()
        self.windowsize = 5
        self.data_packets = data_packets
        self.s = ""
        self.c = 0
    def get_size(self):
        return len(self.buffer)

    def get_sorted_buffer(self):
        unique_seq_nums = set()
        sorted_buffer = []

        for item in sorted(self.buffer, key=lambda x: x.seq_num):
            if item.seq_num not in unique_seq_nums:
                unique_seq_nums.add(item.seq_num)
                sorted_buffer.append(item)
        return sorted_buffer
    def insert_packet(self, packet):
        seq_num = packet.seq_num
        send_base = self.get_send_base()
        if seq_num == send_base:
            self.s+=packet.payload.decode('utf-8')
            if (len(self.buffer) != 0):
                # sorted_buffer = sorted(self.buffer, key=lambda x: x.seq_num)
                sorted_buffer = self.get_sorted_buffer()
                b = send_base + 1
                for packet in sorted_buffer:
                    if packet.seq_num == b:
                        self.s += packet.payload.decode('utf-8')
                        self.buffer.remove(packet)
                        print(f'Sending Data Packets with SeqNum {packet.seq_num} from buffer to user 1')
                        b += 1
            print(f'Sent Data Packet with SeqNum={packet.seq_num} to user')
        elif send_base < seq_num <= send_base + self.windowsize:
            self.buffer.add(packet)
        else:
            print('Discarding packet')

        #sorted_buffer = sorted(self.buffer, key=lambda x: x.seq_num)
        sorted_buffer = self.get_sorted_buffer()
        print("BUFFER CONTAINS: ", sorted_buffer)

        if len(self.buffer) == self.windowsize:
            #sorted_buffer = sorted(self.buffer, key=lambda x: x.seq_num)
            sorted_buffer = self.get_sorted_buffer()
            for packet in sorted_buffer:
                self.s += packet.payload.decode('utf-8')
                print(f'Sending Data Packets with SeqNum {packet.seq_num} from buffer to user 2')
            self.buffer.clear()
            
    def clear(self):
        if(len(self.buffer) != 0):
            #sorted_buffer = sorted(self.buffer, key=lambda x: x.seq_num)
            sorted_buffer = self.get_sorted_buffer()
            for packet in sorted_buffer:
                self.s += packet.payload.decode('utf-8')
                print(f'Sending Data Packets with SeqNum {packet.seq_num} from buffer to user 3')
            self.buffer.clear()


    def get_content_length(self):
        try:
            request =self.s
            request_lines = request.split('\r\n')
            for line in request_lines:
                if line.startswith('Content-Length:'):
                    return int(line.split(': ')[1])
        except Exception as e:
            print(e)


    def prints(self):
        return (self.s)
    def get_received_content_length(self):
        if "\r\r\n\r\r\n" in self.s:
            self.c += len(self.s.split('\r\r\n\r\r\n')[1])
        return self.c
    def get_send_base(self):
        sorted_buffer = sorted(self.data_packets)
        for i, seq_num in enumerate(sorted_buffer, start=1):
            if i != seq_num:
                return i

        return len(sorted_buffer) + 1


terminate = 0
def send_data_thread(file_path, router_addr, router_port, peer_ip, server_port, window_size, conn, ack_queue, sent_packets, last_data_seq_number_sent,  seq_num = 2):
    global terminate
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(1013)
            if not data:
                last_data_seq_number_sent = seq_num - 1
                break
            if seq_num <= ack_queue.get_send_base() + window_size and seq_num+1 >= ack_queue.get_send_base():

                data_packet = Packet(packet_type=Packet.DATA,
                                     seq_num=seq_num,
                                     peer_addr=peer_ip,
                                     peer_port=server_port,
                                     payload=data)
                conn.sendto(data_packet.to_bytes(), (router_addr, router_port))

                print(f'Sent Data with SeqNum={data_packet.seq_num} to router and data is ={data}')
                sent_packets[seq_num] = {
                    'packet': data_packet,
                    'timestamp': time.time()
                }

                seq_num += 1



def monitor_for_timeout(router_addr, router_port, timeout, conn, ack_queue, sent_packets, last_data_seq_number_sent):
    global terminate
    while True:
        if(terminate):
            break
        if last_data_seq_number_sent != -1 and last_data_seq_number_sent == max(ack_queue.received_acks):
            break
        for seq_num, packet_info in list(sent_packets.items()):
            if time.time() - packet_info['timestamp'] > timeout and seq_num+1 not in ack_queue.received_acks:
                conn.sendto(packet_info['packet'].to_bytes(), (router_addr, router_port))
                print(f'Resent Data with SeqNum={packet_info["packet"].seq_num} to router (Timeout)')
                packet_info['timestamp'] = time.time()  # Update the timestamp
                

def receive_ack_thread(conn, ack_queue,sent_packets, last_data_seq_number_sent, method = "get", verbose = 0, output = 0):
    global terminate
    while True:
        if (terminate):
            break
        ack_response, sender = conn.recvfrom(1024)
        ack_packet = Packet.from_bytes(ack_response)
        if ack_packet.is_fin():
            print(f'Received FIN with SeqNum={ack_packet.seq_num} from {sender}')
            fin_ack_packet = Packet(packet_type=Packet.FIN_ACK,
                                    seq_num=ack_packet.seq_num + 1,
                                    peer_addr=ack_packet.get_peer_ip_addr(),
                                    peer_port=ack_packet.get_peer_port(),
                                    payload=b"")
            conn.sendto(fin_ack_packet.to_bytes(), sender)
            print(f'Sent FIN-ACK with SeqNum={fin_ack_packet.seq_num} to {sender}')
            terminate = 1
            break
        if ack_packet.is_data_ack():
            ack_queue.acknowledge(ack_packet.seq_num)
            print(f'Received ACK with SeqNum={ack_packet.seq_num} from router')
            if last_data_seq_number_sent != -1 and last_data_seq_number_sent == max(ack_queue.received_acks):
                break
        if ack_packet.is_data():
            print(f'Received DATA with SeqNum={ack_packet.seq_num} from router')
            if(method == "post"):
                handle_post_packet(ack_packet.payload, verbose, output)
            data_packet = Packet(packet_type=Packet.DATA_ACK,
                                 seq_num=ack_packet.seq_num + 1,
                                 peer_addr=ack_packet.get_peer_ip_addr(),
                                 peer_port=ack_packet.get_peer_port(),
                                 payload=b'')
            router_addr, router_port = sender
            conn.sendto(data_packet.to_bytes(), (router_addr, router_port))
            print(f'Sent DATA-ACK with SeqNum={data_packet.seq_num} to {sender}')

def get_timeout():
    with open("timeout.txt") as f:
        to = float(f.read())
        return to


def handle_post_packet(response, verbose, output):
    headers, body = response.split(b"\r\n\r\n", 1)

    if verbose:
        if output:
            write_to_file(headers.decode('utf-8') + '\n' + body.decode('utf-8'), output)
        else:
            print("\n\n-----------------------------------------------------------\n\n")
            print(headers.decode('utf-8'), '\n', body.decode('utf-8'))
            print("\n\n-----------------------------------------------------------\n\n")
    else:
        if output:
            write_to_file(body.decode('utf-8'), '\n', output)
        else:
            print(body.decode('utf-8'))

def write_to_file(data, filename):
    f = open(filename, 'w')
    f.write(data)
    f.close()