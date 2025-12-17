#!/usr/bin/env python3
"""
chord_query.py
Usage:
  python chord_query.py <existing_node_port> <key_raw>

This script computes the hashed key ID and calls get_key on an arbitrary node
(localhost:<existing_node_port>) — the node will forward the request to the
correct successor if necessary.
"""
import sys
import pickle
import socket
import hashlib

M = 6
NODES = 2 ** M
BUF_SZ = 65536

def sha1_to_id(s: str) -> int:
    h = hashlib.sha1(s.encode('utf-8')).digest()
    return int.from_bytes(h, 'big') % NODES

def call_rpc(host_port, method, *args):
    host, port = host_port
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.sendall(pickle.dumps((method, args)))
            data = b''
            while True:
                part = s.recv(BUF_SZ)
                if not part:
                    break
                data += part
            return pickle.loads(data)
    except Exception as e:
        return ('error', str(e))

def main():
    if len(sys.argv) != 3:
        print("Usage: python chord_query.py <existing_node_port> <key_raw>")
        sys.exit(1)
    port = int(sys.argv[1])
    key_raw = sys.argv[2]
    key_id = sha1_to_id(key_raw)
    node_addr = ('127.0.0.1', port)

    res = call_rpc(node_addr, 'get_key', key_id)
    if isinstance(res, tuple) and res and res[0] == 'error':
        print("RPC error:", res)
    else:
        print("Query:", key_raw, "id", key_id, "=>", res)

if __name__ == '__main__':
    main()