#!/usr/bin/env python3
import socket
import sys
import pickle

if len(sys.argv) != 2:
    print("Usage: python3 peer.py PORT")
    sys.exit(1)

port = int(sys.argv[1])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('', port))
    s.listen(1)
    print(f"Peer running on port {port}")
    while True:
        conn, addr = s.accept()
        with conn:
            data = conn.recv(4096)
            if not data:
                break
            message = pickle.loads(data)
            if message == "BEGIN":
                response = ("OK", f"Happy to meet you, {addr}")
                conn.sendall(pickle.dumps(response))