#!/usr/bin/env python3
"""
chord_populate.py
Usage:
  python chord_populate.py <existing_node_port> <csv_filename>

This script:
 - reads csv rows (expects at least 4 columns),
 - forms key as row[0] + row[3] (playerid + year),
 - hashes to M-bit id using SHA-1, and
 - contacts an arbitrary node (localhost:<existing_node_port>) to find the
   key's successor, then calls add_key on that successor.

This script is defensive about the remote RPC return shape for node tuples.
"""
import csv
import sys
import socket
import pickle
import hashlib

M = 6
NODES = 2 ** M
BUF_SZ = 65536

def sha1_to_id(s: str) -> int:
    h = hashlib.sha1(s.encode('utf-8')).digest()
    return int.from_bytes(h, 'big') % NODES

def call_rpc(host_port, method, *args):
    """
    host_port is a (host, port) tuple here.
    Returns whatever the remote returned (possibly ('error', msg)).
    """
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

def normalize_node_like(node_like):
    """
    Convert a few possible node-like shapes into canonical (id, (host,port)).
    Accepts:
      - (id, (host,port))       -> returned unchanged
      - (id, host, port)        -> converted
      - [id, (host,port)]       -> converted to tuple
    Raises ValueError on unknown shape.
    """
    if isinstance(node_like, tuple) and len(node_like) == 2 and isinstance(node_like[1], tuple):
        return node_like
    if isinstance(node_like, tuple) and len(node_like) == 3:
        nid, host, port = node_like
        return (nid, (host, port))
    if isinstance(node_like, list) and len(node_like) == 2 and isinstance(node_like[1], (list, tuple)):
        return (node_like[0], (node_like[1][0], node_like[1][1]))
    raise ValueError(f"Cannot normalize node-like: {repr(node_like)}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python chord_populate.py <existing_node_port> <csv_filename>")
        sys.exit(1)
    port = int(sys.argv[1])
    filename = sys.argv[2]
    node_addr = ('127.0.0.1', port)

    try:
        with open(filename, newline='') as csvfile:
            reader = csv.reader(csvfile)
            header = next(reader, None)
            for row in reader:
                if len(row) < 4:
                    continue
                key_raw = row[0] + row[3]  # playerid + year
                key_id = sha1_to_id(key_raw)

                # Ask the node we contacted to find the correct successor
                succ = call_rpc(node_addr, 'find_successor', key_id)
                if isinstance(succ, tuple) and succ and succ[0] == 'error':
                    print("Find successor RPC error:", succ)
                    continue

                # Normalize succ into canonical (id, (host,port))
                try:
                    succ = normalize_node_like(succ)
                except ValueError as e:
                    print("Malformed successor returned:", succ, " -- ", e)
                    continue

                # Build value dict and call add_key on the successor's host:port
                value = {f"col{i}": v for i, v in enumerate(row)}
                succ_hostport = succ[1]  # (host,port)
                res = call_rpc(succ_hostport, 'add_key', key_id, value)
                if isinstance(res, tuple) and res and res[0] == 'error':
                    print("add_key RPC error:", res)
                else:
                    print(f"Added {key_raw} id={key_id} -> node {succ[0]}")
    except FileNotFoundError:
        print("CSV file not found:", filename)
        sys.exit(1)

if __name__ == '__main__':
    main()