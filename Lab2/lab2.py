"""
CPSC 5520 - Lab 2: Bully Election Algorithm with Extra Credit
Seattle University
Author: Ramya Ramesh
"""

import pickle
import random
import socket
import socketserver
import sys
import threading
import time


class BullyNode:
    """A node implementing the Bully Election Algorithm with optional probe and failure simulation."""

    # ==============================
    # CONSTANTS
    # ==============================
    BUF_SIZE = 1024

    MSG_HOWDY = "HOWDY"
    MSG_ELECTION = "ELECT"
    MSG_LEADER = "I_AM_LEADER"
    MSG_PROBE = "PROBE"
    GOT_IT = "GOT_IT"

    PROBE_INTERVAL_RANGE = (0.5, 3.0)
    FAIL_INTERVAL_RANGE = (0, 10)
    FAIL_DURATION_RANGE = (1, 4)

    def __init__(self, days_to_birthday, su_id, port, gcd_host, gcd_port):
        self.node_id = (days_to_birthday, su_id)
        self.listen_addr = ("localhost", port)

        self.gcd_host = gcd_host
        self.gcd_port = gcd_port

        self.peers = {}
        self.leader = None
        self.election_active = False
        self.failed = False
        self.responded = False

        # Locks for thread safety
        self.lock = threading.Lock()
        self.peers_lock = threading.Lock()

        # Server placeholder
        self.server = None

    # ==============================
    # UTILITY METHODS
    # ==============================
    def safe_print(self, message):
        with self.lock:
            print(message)

    def update_peers(self, new_peers):
        self.safe_print(f"[{self.node_id}] Updating peers: {list(new_peers.keys())}")
        with self.peers_lock:
            self.peers.clear()
            self.peers.update(new_peers)
        return self.peers

    def get_higher_nodes(self):
        """Get list of nodes with higher IDs."""
        self.safe_print(f"[{self.node_id}] Checking for higher nodes...")
        with self.peers_lock:
            return [pid for pid in self.peers.keys() if pid > self.node_id]

    # ==============================
    # COMMUNICATION
    # ==============================
    def send_message(self, target_id, msg_type):
        """Send a pickled message to target node."""
        if self.failed:
            return

        try:
            self.safe_print(f"[{self.node_id}] Sending {msg_type} to {target_id}")
            addr = self.peers[target_id]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(addr)
                message = ((msg_type, self.peers), (self.node_id, target_id))
                s.sendall(pickle.dumps(message))

                response = pickle.loads(s.recv(self.BUF_SIZE))
                if msg_type in [self.MSG_ELECTION, self.MSG_PROBE] and response == self.GOT_IT:
                    self.responded = True
                    self.safe_print(f"[{self.node_id}] Received {self.GOT_IT} from {target_id}")
        except Exception:
            pass  # Ignore unreachable peers

    def wait_for_response(self, timeout=3):
        """Wait for a response within a timeout period."""
        start = time.time()
        while time.time() - start < timeout:
            if self.responded:
                return True
            time.sleep(0.1)
        return False

    # ==============================
    # ELECTION LOGIC
    # ==============================
    def start_election(self):
        """Initiate the Bully election process."""
        with self.lock:
            if self.election_active or self.failed:
                return
            self.election_active = True

        self.safe_print(f"[{self.node_id}] Starting election...")
        higher_nodes = self.get_higher_nodes()

        if not higher_nodes:
            self.safe_print(f"[{self.node_id}] No higher nodes found. Announcing self as leader.")
            self.announce_leader()
            self.election_active = False
            return

        self.safe_print(f"[{self.node_id}] Notifying higher nodes: {higher_nodes}")
        for pid in higher_nodes:
            self.send_message(pid, self.MSG_ELECTION)

        got_response = self.wait_for_response()
        if not got_response:
            self.safe_print(f"[{self.node_id}] No responses from higher nodes. Announcing self as leader.")
            self.announce_leader()
        else:
            self.safe_print(f"[{self.node_id}] Awaiting leader announcement...")

        self.responded = False
        with self.lock:
            self.election_active = False

    def announce_leader(self):
        """Announce self as leader to all peers."""
        self.leader = self.node_id
        self.safe_print(f"Victory! [{self.node_id}] I am the new LEADER - no bigger bully than me!")

        self.safe_print(f"[{self.node_id}] Announcing leadership to peers...")
        for pid in self.peers:
            if pid != self.node_id:
                self.send_message(pid, self.MSG_LEADER)

    # ==============================
    # MESSAGE HANDLER
    # ==============================
    def handle_message(self, message, request):
        """Handle incoming message from peers."""
        (msg_data, communication) = message
        msg_type, peers = msg_data
        sender_id, recv_id = communication

        self.safe_print(f"[{self.node_id}] Received {msg_type} from {sender_id}")
        self.update_peers(peers)

        if self.failed:
            return

        if msg_type == self.MSG_ELECTION:
            request.sendall(pickle.dumps(self.GOT_IT))
            self.start_election()

        elif msg_type == self.MSG_LEADER:
            self.leader = sender_id
            self.safe_print(f"[{self.node_id}] Recognized {self.leader} as leader")

        elif msg_type == self.MSG_PROBE:
            request.sendall(pickle.dumps(self.GOT_IT))

        else:
            self.safe_print(f"[{self.node_id}] Unknown message: {msg_type}")

    # ==============================
    # SERVER SETUP
    # ==============================
    class NodeHandler(socketserver.BaseRequestHandler):
        def handle(self):
            raw = self.request.recv(BullyNode.BUF_SIZE)
            try:
                message = pickle.loads(raw)
                self.server.node.handle_message(message, self.request)
            except Exception:
                pass

    def start_server(self):
        """Start threaded TCP server."""
        self.server = socketserver.ThreadingTCPServer(self.listen_addr, self.NodeHandler)
        self.server.node = self
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()

    # ==============================
    # GCD REGISTRATION
    # ==============================
    def register_with_gcd(self):
        """Register this node with the GCD."""
        msg = (self.MSG_HOWDY, (self.node_id, self.listen_addr))
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.gcd_host, self.gcd_port))
                s.sendall(pickle.dumps(msg))
                data = s.recv(self.BUF_SIZE)
                peers = pickle.loads(data)
                self.safe_print(f"[{self.node_id}] Registered with GCD. Peers: {list(peers.keys())}")
                return peers
        except Exception as e:
            self.safe_print(f"[{self.node_id}] Registration failed: {e}")
            sys.exit(1)

    # ==============================
    # EXTRA CREDIT: PROBE
    # ==============================
    def probe_leader(self):
        """Continuously probe the leader to check for failure."""
        while True:
            if self.failed:
                time.sleep(2)
                continue

            if self.leader and self.leader != self.node_id:
                self.safe_print(f"[{self.node_id}] Probing leader {self.leader}...")
                addr = self.peers.get(self.leader)
                if addr:
                    self.send_message(self.leader, self.MSG_PROBE)
                    responded = self.wait_for_response()
                    if not responded:
                        self.safe_print(f"[{self.node_id}] Leader {self.leader} not responding. Starting new election.")
                        self.peers = self.update_peers(self.register_with_gcd())
                        self.start_election()
                    else:
                        self.responded = False
            time.sleep(random.uniform(*self.PROBE_INTERVAL_RANGE))

    # ==============================
    # EXTRA CREDIT: FAILURE SIMULATION
    # ==============================
    def simulate_failure(self):
        """Simulate random node failures and recovery."""
        while True:
            time.sleep(random.uniform(*self.FAIL_INTERVAL_RANGE))
            self.failed = True
            self.safe_print(f"[{self.node_id}] Simulating failure...")
            time.sleep(random.uniform(*self.FAIL_DURATION_RANGE))
            self.failed = False
            self.safe_print(f"[{self.node_id}] Recovered. Rejoining network...")
            self.register_with_gcd()
            self.start_election()

    # ==============================
    # MAIN LOOP
    # ==============================
    def run(self):
        self.safe_print(f"Node {self.node_id} starting on port {self.listen_addr[1]}...")
        self.start_server()
        self.peers = self.register_with_gcd()

        # Start background threads
        threading.Thread(target=self.probe_leader, daemon=True).start()
        threading.Thread(target=self.simulate_failure, daemon=True).start()

        time.sleep(random.uniform(1, 3))
        self.start_election()

        while True:
            time.sleep(2)


# ==============================
# ENTRY POINT
# ==============================
if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python3 lab2.py <days_to_birthday> <su_id> <port> <gcd_host> <gcd_port>")
        sys.exit(1)

    days_to_birthday = int(sys.argv[1])
    su_id = int(sys.argv[2])
    port = int(sys.argv[3])
    gcd_host = sys.argv[4]
    gcd_port = int(sys.argv[5])

    node = BullyNode(days_to_birthday, su_id, port, gcd_host, gcd_port)
    node.run()