import socket
import threading
import argparse
import udp_server
from file_server_application import handle_get_request, handle_post_request
import time
def run_server(host, port, data_dir, verbose):
    t = threading.Thread(target=udp_server.run_server, args=(port, data_dir))
    t.start()
    t.join()

parser = argparse.ArgumentParser()
parser.add_argument("--port", "-p", help="echo server port", type=int, default=8080)
parser.add_argument("-v", "--verbose", action='store_true', help="verbose")
parser.add_argument("-d", "--data_dir", help="Specify the data directory", default='.')
args = parser.parse_args()
run_server('', args.port, args.data_dir, args.verbose)
