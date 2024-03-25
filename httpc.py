import argparse
import socket
import sys, os
from urllib.parse import urlparse
import time
import udp_client
from packet import Packet
import ipaddress
from send_receive_utility import AckQueue
from send_receive_utility import ReceiverBuffer
from send_receive_utility import get_timeout

ack_queue = AckQueue()
data_packets = set()
data_in_data_packets = set()

# Function to write data to a file
def write_to_file(data, filename):
    f = open(filename, 'w')
    f.write(data)
    f.close()

# Function to read data from a file
def read_from_file(filename):
    f = open(filename)
    data = f.read().strip()
    f.close()
    return data

# Function to handle POST request
def post_request(content_type, data, routerhost, routerport, serverhost, serverport, verbose, output):
    parsed_url = urlparse(serverhost)    #http://localhost/
    serverhost = parsed_url.netloc
    path       = parsed_url.path or '/'
    query      = parsed_url.query
    file_dir   = os.environ.get("FILE_DIR")
    user_agent = read_from_file(file_dir + "/print_messages/user_agent")

    if query:
        path += '?' + query
    try:

        request = f"POST {path} HTTP/1.0\r\n"
        request += f"Host: {serverhost}\r\n"
        if content_type:
            request += content_type + "\r\n"
        request += f"Content-Length: {len(data)}\r\n"
        request += f"User-Agent: {user_agent}\r\n"
        request += "Connection:close\r\n\r\n"
        request += data

        f = open("temp.txt", 'w')
        f.write(request)
        f.close()
        file_path = "temp.txt"

        udp_client.run_client(routerhost, routerport, serverhost, serverport, file_path, verbose, output)
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        print(open(file_dir + '/print_messages/help_post.txt').read())
    finally:
        pass
    
def get_request(content_type, routerhost, routerport, serverhost, serverport, verbose=False, output=None):
    global ack_queue
    global data_packets
    global data_in_data_packets
    timeout = get_timeout()
    data_packets.add(1)
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn.bind(('localhost', 0))

    parsed_url = urlparse(serverhost) 
    serverhost = parsed_url.netloc
    path = parsed_url.path or '/'
    query = parsed_url.query
    file_dir = os.environ.get("FILE_DIR")
    user_agent = read_from_file(file_dir + "/print_messages/user_agent")
    serverhost = ipaddress.ip_address(socket.gethostbyname(serverhost))
    if query:
        path += '?' + query
    user_agent = read_from_file(file_dir + "/print_messages/user_agent")
    try:
        seq_num = 1
        syn_packet = Packet(packet_type=Packet.SYN,
                            seq_num=seq_num,
                            peer_addr=serverhost,
                            peer_port=serverport,
                            payload=b"")
        conn.sendto(syn_packet.to_bytes(), (routerhost, routerport))
        timestamp = time.time()
        print(f'Sent SYN with SeqNum={syn_packet.seq_num} to router')
        conn.settimeout(timeout)
        while True:
            if time.time() - timestamp > timeout:
                syn_packet = Packet(packet_type=Packet.SYN,
                                    seq_num=seq_num,
                                    peer_addr=serverhost,
                                    peer_port=serverport,
                                    payload=b"")
                conn.sendto(syn_packet.to_bytes(), (routerhost, routerport))
                timestamp = time.time()
                print(f'Sent SYN with SeqNum={syn_packet.seq_num} to router')
            try:
                syn_ack_response, sender = conn.recvfrom(1024)
                syn_ack_packet = Packet.from_bytes(syn_ack_response)
                ack_queue.received_acks.add(1)
                print(f'Received SYN-ACK with SeqNum={syn_ack_packet.seq_num} from {sender}')
                ack_queue.received_acks.add(2)
                if syn_ack_packet.is_syn_ack():
                    break
                if not syn_ack_packet.is_syn_ack():
                    print("Invalid SYN-ACK packet received. Trying again.")
            except:
                syn_packet = Packet(packet_type=Packet.SYN,
                                    seq_num=seq_num,
                                    peer_addr=serverhost,
                                    peer_port=serverport,
                                    payload=b"")
                conn.sendto(syn_packet.to_bytes(), (routerhost, routerport))
                timestamp = time.time()
                print(f'Sent SYN with SeqNum={syn_packet.seq_num} to router')
        conn.settimeout(None)
        seq_num+=1
        request = f"GET {path} HTTP/1.0\r\n"
        request += f"Host: {serverhost}\r\n"
        if content_type:
            request += content_type + "\r\n"
        request += f"User-Agent: {user_agent}\r\n"
        request += "Connection: close\r\n\r\n"
        f = open("temp2.txt", 'w')
        f.write(request)
        f.close()
        file_path = "temp2.txt"

        sender = routerhost, routerport
        with open(file_path, 'rb') as file:

            data = file.read(1013)
            data_packet = Packet(packet_type=Packet.DATA,
                                 seq_num=seq_num,
                                 peer_addr=serverhost,
                                 peer_port=serverport,
                                 payload=data)
            conn.sendto(data_packet.to_bytes(), (routerhost, routerport))
            print(f'Sent DATA with SeqNum={data_packet.seq_num} to router')
            timestamp = time.time()
            conn.settimeout(timeout)
            while True:
                if time.time() - timestamp > timeout:
                    data_packet = Packet(packet_type=Packet.DATA,
                                         seq_num=seq_num,
                                         peer_addr=serverhost,
                                         peer_port=serverport,
                                         payload=data)
                    conn.sendto(data_packet.to_bytes(), sender)
                    timestamp = time.time()
                    print(f'Sent DATA with SeqNum={data_packet.seq_num} to router')
                try:
                    ack_response, sender = conn.recvfrom(1024)
                    ack_packet = Packet.from_bytes(ack_response)
                    print(f'Received DATA ACK with SeqNum={ack_packet.seq_num} from {sender}')
                    if ack_packet.is_data_ack():
                        break
                    if not ack_packet.is_data_ack():
                        print("Invalid ACK packet received. Trying again.")
                except:
                    data_packet = Packet(packet_type=Packet.DATA,
                                         seq_num=seq_num,
                                         peer_addr=serverhost,
                                         peer_port=serverport,
                                         payload=data)
                    conn.sendto(data_packet.to_bytes(), sender)
                    timestamp = time.time()
                    print(f'Sent DATA with SeqNum={data_packet.seq_num} to router')
            conn.settimeout(None)
            receiver_buffer = ReceiverBuffer(data_packets)
            stop_monitoring = 0
            while 1:
                if(stop_monitoring):
                    break
                data, sender = conn.recvfrom(1024)
                packet = Packet.from_bytes(data)
                if packet.is_data():
                    print(f'Received Data packet with SeqNum={packet.seq_num} from {sender}')
                    receiver_buffer.insert_packet(packet)
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
                    for i in data_in_data_packets:
                        if '\r\n\r\n' in i:
                            c += len(i.split('\r\n\r\n')[1])
                        else:
                            c += len(i)
                    if(receiver_buffer.get_content_length() == c):


                        fin_packet = Packet(packet_type=Packet.FIN,
                                            seq_num=seq_num ,
                                            peer_addr=packet.get_peer_ip_addr(),
                                            peer_port=packet.get_peer_port(),
                                            payload=b"")
                        conn.sendto(fin_packet.to_bytes(), sender)
                        timestamp = time.time()
                        print(f'Sent FIN with SeqNum={fin_packet.seq_num} to router')
                        conn.settimeout(timeout)
                        counter = 0
                        while True:
                            if time.time() - timestamp > timeout:
                                fin_packet = Packet(packet_type=Packet.FIN,
                                                    seq_num= seq_num,
                                                    peer_addr=packet.get_peer_ip_addr(),
                                                    peer_port=packet.get_peer_port(),
                                                    payload=b"")
                                conn.sendto(fin_packet.to_bytes(), sender)
                                timestamp = time.time()
                                print(f'Sent FIN with SeqNum={fin_packet.seq_num} to router')
                            try:
                                ack_response, sender = conn.recvfrom(1024)
                                ack_packet = Packet.from_bytes(ack_response)
                                print(f'Received FIN ACK with SeqNum={ack_packet.seq_num} from {sender}')
                                handle_get_response(receiver_buffer.prints().encode('utf-8'), verbose, output)
                                if ack_packet.is_fin_ack():
                                    stop_monitoring = 1
                                    break
                                if not ack_packet.is_fin_ack():
                                    print("Invalid ACK packet received. Trying again.")
                            except:
                                fin_packet = Packet(packet_type=Packet.FIN,
                                                    seq_num=seq_num,
                                                    peer_addr=packet.get_peer_ip_addr(),
                                                    peer_port=packet.get_peer_port(),
                                                    payload=b"")
                                conn.sendto(fin_packet.to_bytes(), sender)
                                timestamp = time.time()
                                print(f'Sent FIN with SeqNum={fin_packet.seq_num} to router')
                                counter += 1
                                if(counter == 5):
                                    print(f'Received FIN ACK with SeqNum={fin_packet.seq_num+1} from {sender}')
                                    exit(0)
                        conn.settimeout(None)
 
    except Exception as e:
        print(open(file_dir + '/print_messages/help_get.txt').read())
        print(e)
    finally:
        pass

def handle_get_response(response, verbose, output):
    headers, body = response.split(b"\r\n\r\n", 1)
    headers = headers.decode('utf-8')
    status_code = float(headers.split('\r\n')[0].split(' ')[1])
    location = headers.split('location: ')[1].split('\r\n')[0] if 'location: ' in headers else headers.split('Location: ')[1].split('\r\n')[0] if 'Location: ' in headers else None
    if 300 <= status_code < 400 and location:

        parsed_location = urlparse(location.strip())
        host = parsed_location.netloc or host
        path = parsed_location.path or '/'
        query = parsed_location.query
        if query:
            path += '?' + query
    if verbose:
        if output:
            write_to_file(headers + '\n' + body.decode('utf-8'), output)
        else:
            print("\n\n-----------------------------------------------------------\n\n")
            print(headers, '\n',  body.decode('utf-8'))
            print("\n\n-----------------------------------------------------------\n\n")
    else:
        if output:
            write_to_file(body.decode('utf-8') + '\n' , output)
        else:
            print("\n\n-----------------------------------------------------------\n\n")
            print(body.decode('utf-8'))
            print("\n\n-----------------------------------------------------------\n\n")

def main():
    parser = argparse.ArgumentParser(
                    prog='httpc',
                    description='Implement curl',
                    epilog='Use "httpc help [command]" for more information about a command.',
                    add_help=False)



    subparsers = parser.add_subparsers(title='subcommands', dest='command', metavar='COMMAND')

    # Subcommand: help
    help_parser = subparsers.add_parser('help', help='Show help message for a command')

    help_parser.add_argument('command_name', choices=['get', 'post'], help='Specify the command to get help for', default=None,  nargs='?')

    
    # Subcommand: get
    get_parser = subparsers.add_parser('get', help='Perform a GET request')
    #get_parser.add_argument('URL', help='The URL to send the GET request to')
    get_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    get_parser.add_argument('-H', '--header', help='Type of data', required=False)
    get_parser.add_argument('-o', '--output', help='Write output to file')
    get_parser.add_argument("--routerhost", help="router host", default="localhost")
    get_parser.add_argument("--routerport", help="router port", type=int, default=3000)
    get_parser.add_argument("--serverhost", help="server host", default="localhost")
    get_parser.add_argument("--serverport", help="server port", type=int, default=8007)

    # Subcommand: post
    post_parser = subparsers.add_parser('post', help='Perform a POST request')
    #post_parser.add_argument('URL', help='The URL to send the POST request to')
    post_parser.add_argument('-d', '--data', help='Data to include in the POST request')
    post_parser.add_argument('-f', '--file', help='File Containing data to include in the POST request')
    post_parser.add_argument('-H', '--header', help='Type of data to post', required=False)
    post_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    post_parser.add_argument('-o', '--output', help='Write output to file')
    post_parser.add_argument("--routerhost", help="router host", default="localhost")
    post_parser.add_argument("--routerport", help="router port", type=int, default=3000)
    post_parser.add_argument("--serverhost", help="server host", default="localhost")
    post_parser.add_argument("--serverport", help="server port", type=int, default=8007)
    #post_parser.add_argument("--file", help="file path for transfer", required=True)
    args = parser.parse_args()
    


    file_dir = os.environ.get("FILE_DIR")

    if args.command == 'help':
        if args.command_name == 'get':
            print(open(file_dir + '/print_messages/help_get.txt').read())
        elif args.command_name == 'post':
            print(open(file_dir + '/print_messages/help_post.txt').read())
        else:
            print(open(file_dir + '/print_messages/help.txt').read())
    elif args.command == 'get':
        content_type = ''
        if args.header:
            content_type = args.header 
        if content_type and ':' not in content_type:
                print("-H accepts header as k:v format")
        else:
            get_request(content_type, args.routerhost, args.routerport, args.serverhost, args.serverport, args.verbose, args.output)
    elif args.command == 'post':
        if args.data and args.file:
            print("-d and -f cannot be used together")
        elif args.data:
            content_type = ':'
            if args.header:
                content_type = args.header
            if ':' not in content_type:
                print("-H accepts header as k:v format")
            else:
                post_request(content_type, args.data, args.routerhost, args.routerport, args.serverhost, args.serverport, args.verbose, args.output)
        else:
            try:
                content_type = ''
                if args.header:
                    content_type = args.header
                if content_type and ':' not in content_type:
                    print("-H accepts header as k:v format")
                else:
                    fl = open(args.file)
                    content_type = ''
                    if args.header:
                        content_type = args.header
                    post_request(args.header, fl.read().strip(), args.routerhost, args.routerport, args.serverhost, args.serverport, args.verbose, args.output)
            except FileNotFoundError:
                print("File provided under -f option does not exist")


if __name__ == "__main__":
    main()
