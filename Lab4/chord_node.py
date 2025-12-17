#!/usr/bin/env python3
"""
chord_node.py
Usage:
  python chord_node.py <known_node_port_or_0>

If known_node_port_or_0 == 0: start a new network (this node is alone).
Otherwise join the network via the known node.
"""
import socket, threading, pickle, sys, hashlib, argparse, time
from typing import Tuple

# TEST-TUNABLE
M = 6
NODES = 2 ** M
BUF_SZ = 65536

def sha1_to_id(s: str) -> int:
    h = hashlib.sha1(s.encode('utf-8')).digest()
    return int.from_bytes(h, 'big') % NODES

class ModRange:
    def __init__(self, start, stop, divisor):
        self.divisor = divisor
        self.start = start % divisor
        self.stop = stop % divisor
        if self.start < self.stop:
            self.intervals = (range(self.start, self.stop),)
        elif self.stop == 0:
            self.intervals = (range(self.start, self.divisor),)
        else:
            self.intervals = (range(self.start, self.divisor), range(0, self.stop))
    def __contains__(self, idv):
        for interval in self.intervals:
            if idv in interval:
                return True
        return False
    def __repr__(self):
        return f"<ModRange [{self.start},{self.stop}) mod {self.divisor}>"

class FingerEntry:
    def __init__(self, n, k, node=None):
        if not (0 <= n < NODES and 0 < k <= M):
            raise ValueError('invalid finger entry values')
        self.start = (n + 2**(k-1)) % NODES
        self.next_start = (n + 2**k) % NODES if k < M else n
        self.interval = ModRange(self.start, self.next_start, NODES)
        self.node = node

class ChordNode:
    def __init__(self, node_id: int, addr: Tuple[str,int]):
        self.node = node_id
        self.addr = addr
        self.finger = [None] + [FingerEntry(node_id, k) for k in range(1, M+1)]
        self.predecessor = None  # (id,(host,port))
        self.keys = {}  # id -> value
        self.lock = threading.Lock()
        for i in range(1, M+1):
            self.finger[i].node = (self.node, self.addr)

    @property
    def successor(self):
        return self.finger[1].node

    @successor.setter
    def successor(self, node_tuple):
        self.finger[1].node = node_tuple

    def __repr__(self):
        pred = self.predecessor[0] if self.predecessor else None
        succ = self.successor[0] if self.successor else None
        return f"<Node id={self.node} addr={self.addr} pred={pred} succ={succ} keys={len(self.keys)}>"

    def normalize_node_tuple(self, node_tuple):
        """
        Normalize various node tuple shapes into (id, (host, port)).
        Returns None if the tuple is an error or invalid.
        Acceptable inputs:
            (id, (host,port))
            (id, host, port)
        Rejects:
            ('error', msg)
        """
        if node_tuple is None:
            return None
        # Case: ('error', msg)
        if isinstance(node_tuple, tuple) and len(node_tuple) == 2:
            nid, second = node_tuple
            if isinstance(nid, str) and nid == 'error':
                return None
            # Correct format (id, (host,port))
            if isinstance(second, tuple) and len(second) == 2:
                return (nid, second)
        # Case (id, host, port)
        if isinstance(node_tuple, tuple) and len(node_tuple) == 3:
            nid, host, port = node_tuple
            return (nid, (host, port))
        return None

    # ----------------- rpc client -----------------
    def call_rpc(self, node_tuple, method, *args):
        print(f"\nRPC call_rpc to {node_tuple} method {method} args {args}\n")

        if node_tuple is None:
            raise RuntimeError("call_rpc to None")
        
        nid, (host, port) = node_tuple
        try:
            with socket.create_connection((host, port), timeout=3) as s:
                print(f"\nRPC connected to {(host, port)}\n")
                s.sendall(pickle.dumps((method, args)))
                data = b''
                while True:
                    part = s.recv(BUF_SZ)
                    if not part:
                        break
                    data += part
                return pickle.loads(data)
        except Exception as e:
            print(f"\nRPC error calling {(host, port)} method {method} args {args}: {e}\n")
            return ('error', str(e))

    # ----------------- core chord ops -----------------
    def find_successor(self, idv):
        npred = self.find_predecessor(idv)
        succ = self.call_rpc(npred, 'get_successor')
        return self.normalize_node_tuple(succ)

    def find_predecessor(self, idv):
        n = (self.node, self.addr)
        while True:
            succ = self.call_rpc(n, 'get_successor')
            if isinstance(succ, tuple) and succ[0] == 'error': 
                return n
            succ_id = succ[0]
            # if id in (n, succ]
            if idv in ModRange((n[0] + 1) % NODES, (succ_id + 1) % NODES, NODES):
                return n
            else:
                cand = self.call_rpc(n, 'closest_preceding_finger', idv)
                cand = self.normalize_node_tuple(cand)
                if cand is None:
                    return n
                n = cand

    def closest_preceding_finger(self, idv):
        for i in range(M, 0, -1):
            node_i = self.finger[i].node
            if node_i is None: continue
            nid = node_i[0]
            if nid in ModRange((self.node+1)%NODES, idv, NODES):
                return node_i
        return (self.node, self.addr)

    def join(self, known_node_tuple):
        print(f"Joining network via known node: {known_node_tuple}")
        if known_node_tuple is None:
            # start new ring
            self.predecessor = (self.node, self.addr)
            self.successor = (self.node, self.addr)
        else:
            succ = self.call_rpc(known_node_tuple, 'find_successor', self.node)
            succ = self.normalize_node_tuple(succ)
            if succ is None:
                print("ERROR: find_successor returned invalid successor:", succ)
                return
            self.successor = succ
            # notify successor that I may be its predecessor
            if self.successor is None:
                print("ERROR: successor is None, cannot notify.")
                return
            _ = self.call_rpc(self.successor, 'notify', (self.node, self.addr))
            # transfer keys that successor should give to me
            moved = self.call_rpc(self.successor, 'transfer_keys', (self.node, self.addr))
            if isinstance(moved, dict):
                with self.lock:
                    for k,v in moved.items():
                        self.keys[k] = v
        # update others' finger tables (rigorous, no optimizations)
        self.update_others()

    def update_others(self):
        for i in range(1, M+1):
            id_to_find = (self.node - 2**(i-1) + 1 + NODES) % NODES
            p = self.find_predecessor(id_to_find)
            self.call_rpc(p, 'update_finger_table', (self.node, self.addr), i)

    def update_finger_table(self, s_tuple, i):
        s_id = s_tuple[0]
        fi = self.finger[i]
        curr_node_id = fi.node[0]
        if fi.start != curr_node_id and s_id in ModRange(fi.start, curr_node_id, NODES):
            fi.node = s_tuple
            p = self.predecessor
            if p and p != (self.node, self.addr):
                self.call_rpc(p, 'update_finger_table', s_tuple, i)
            return True
        return False

    # --------------- data operations ----------------
    def add_key(self, key_id, value):
        # route to successor responsible for key
        succ = self.find_successor(key_id)
        if succ[0] == self.node:
            with self.lock:
                self.keys[key_id] = value
            return True
        else:
            return self.call_rpc(succ, 'add_key', key_id, value)

    def get_key(self, key_id):
        with self.lock:
            if key_id in self.keys:
                return self.keys[key_id]
        # not local -> forward to successor (find_successor will return correct node)
        succ = self.find_successor(key_id)
        if succ[0] == self.node:
            return None
        return self.call_rpc(succ, 'get_key', key_id)

    # transfer keys that should belong to new_node (new_node is (id,(h,p)))
    # successor will move keys k in (pred_of_successor, new_node]
    def transfer_keys(self, new_node_tuple):
        new_id = new_node_tuple[0]
        pred = self.predecessor
        if pred is None:
            # if no predecessor, nothing to move
            return {}
        to_move = {}
        with self.lock:
            for k in list(self.keys.keys()):
                if k in ModRange((pred[0] + 1) % NODES, (new_id + 1) % NODES, NODES):
                    to_move[k] = self.keys.pop(k)
        return to_move

    # ----------------- RPC dispatch for server -----------------
    def dispatch_rpc(self, method, args):
        try:
            if method == 'get_successor':
                return self.successor
            elif method == 'get_predecessor':
                return self.predecessor
            elif method == 'find_successor':
                return self.find_successor(args[0])
            elif method == 'find_predecessor':
                return self.find_predecessor(args[0])
            elif method == 'closest_preceding_finger':
                return self.closest_preceding_finger(args[0])
            elif method == 'notify':
                u = args[0]
                if (self.predecessor is None) or (u[0] in ModRange((self.predecessor[0]+1)%NODES, self.node, NODES)):
                    self.predecessor = u
                return True
            elif method == 'update_finger_table':
                s_tuple, i = args
                return self.update_finger_table(s_tuple, i)
            elif method == 'add_key':
                key_id, val = args
                return self.add_key(key_id, val)
            elif method == 'get_key':
                key_id = args[0]
                with self.lock:
                    return self.keys.get(key_id, None)
            elif method == 'transfer_keys':
                new_node_tuple = args[0]
                return self.transfer_keys(new_node_tuple)
            elif method == 'print_fingers':
                # return concise finger table for trace
                res = []
                for i in range(1, M+1):
                    res.append((i, self.finger[i].start, self.finger[i].node[0]))
                return res
            else:
                return ('error', f'unknown method {method}')
        except Exception as e:
            return ('error', str(e))

# ---------------- server ----------------
def start_server(chord_node: ChordNode):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 0))
    server.listen(100)
    host, port = server.getsockname()
    chord_node.addr = (host, port)

    print(f"Node final addr: {(host,port)}")
    for i in range(1, M+1):
        chord_node.finger[i].node = (chord_node.node, chord_node.addr)
    print(f"Node started: id={chord_node.node} addr={chord_node.addr}")
    sys.stdout.flush()

    def handle_client(conn, addr):
        print(f"Connection from {addr}")
        try:
            data = b''
            while True:
                part = conn.recv(BUF_SZ)
                if not part:
                    break
                data += part
            if not data:
                return
            method, args = pickle.loads(data)
            res = chord_node.dispatch_rpc(method, args)
            conn.sendall(pickle.dumps(res))
        except Exception as e:
            try:
                conn.sendall(pickle.dumps(('error', str(e))))
            except:
                pass
        finally:
            conn.close()

    def accept_loop():
        while True:
            client, caddr = server.accept()
            threading.Thread(target=handle_client, args=(client, caddr), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return chord_node.addr

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('known_port', type=int)
    print(f"known_port arg parsed as {p.parse_args().known_port}")
    return p.parse_args()

def main():
    args = parse_args()
    # bind ephemeral port to learn final port
    temp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp.bind(('127.0.0.1', 0))
    h, p = temp.getsockname()
    temp.close()
    node_id = sha1_to_id(f"{h}:{p}")
    print(f"Temporary bind at {(h,p)} to compute node ID - {node_id}")
    node = ChordNode(node_id, (h, p))

    print(f"Initial node id {node_id} at temp addr {(h,p)}")

    print("Starting server...")
    addr = start_server(node)

    # recompute id with final port
    node_id = sha1_to_id(f"{addr[0]}:{addr[1]}")
    node.node = node_id
    for i in range(1, M+1):
        node.finger[i].node = (node.node, node.addr)
    node.predecessor = (node.node, node.addr)

    if args.known_port == 0:
        print("Starting new network (single node).")
        node.join(None)
    else:
        known = ('127.0.0.1', args.known_port)
        known_tuple = (sha1_to_id(f"{known[0]}:{known[1]}"), known)
        print(f"Joining via known node {known} (id {known_tuple[0]})\n")
        node.join(known_tuple)

    # periodic status prints for grading trace
    try:
        while True:
            time.sleep(10000)
            print(node)
            # small finger table print
            ft = node.dispatch_rpc('print_fingers', ())
            print("Fingers:", ft)
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("Shutting down.")

if __name__ == '__main__':
    main()