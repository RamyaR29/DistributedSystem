#!/usr/bin/env python3
import socket
import sys
import pickle

if len(sys.argv) != 2:
    print("Usage: python3 gcd.py PORT")
    sys.exit(1)

port = int(sys.argv[1])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('', port))
    s.listen(1)
    print(f"GCD running on port {port}")
    while True:
        conn, addr = s.accept()
        with conn:
            data = conn.recv(4096)
            if not data:
                break
            message = pickle.loads(data)
            if message == "HOWDY":
                # Send back a list of members
                members = [
                    {"host": "localhost", "port": 5001},
                    {"host": "localhost", "port": 5002}
                ]
                conn.sendall(pickle.dumps(members))