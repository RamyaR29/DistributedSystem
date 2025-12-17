
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

# ==============================
# CONFIGURATION
# ==============================
BUF_SZ = 1024
GCD_HOST = "localhost"
GCD_PORT = 8000
PROBE_INTERVAL_RANGE = (0.5, 3.0)  # seconds between probes
FAIL_INTERVAL_RANGE = (0, 10)  # seconds before simulated failure
FAIL_DURATION_RANGE = (1, 4)  # seconds failure lasts

# ==============================
# GLOBAL STATE
# ==============================
PEERS = {}
PEERS_LOCK = threading.Lock()  # for thread safety
LEADER = None
NODE_ID = None
LISTENER = None
SERVER = None
ELECTION_ACTIVE = False
IS_FAILED = False
LOCK = threading.Lock()
responded = False

# ==============================
# UTILITY FUNCTIONS
# ==============================
def safe_print(msg):
    with LOCK:
        print(msg)

def update_peers(new_peers):
    global PEERS
    with PEERS_LOCK:
        PEERS.clear()
        PEERS.update(new_peers)
    return PEERS

def get_higher_nodes(node_id):
    with PEERS_LOCK:
        return [pid for pid in PEERS.keys() if pid > node_id and pid != node_id]

def send_message(communication, message):
    """Send a pickled message to given (host, port)."""

    (sender_id, recv_id) = communication
    (msg_type, peers) = message
    global IS_FAILED, responded
    print(f"[{sender_id}] Sending a {msg_type} message to {recv_id}")

    if IS_FAILED:
        return  # simulate no network activity when failed
    try:
        recv_addr = PEERS[recv_id]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(recv_addr)

            message_to_send = (message,communication)

            s.sendall(pickle.dumps(message_to_send))
            response = pickle.loads(s.recv(BUF_SZ))

            if(msg_type == "ELECTION" and response == "GOT_IT"):
                responded = True
                print(f"GOT_IT response received from {recv_id}")

            elif message[0] == "PROBE" and response == "GOT_IT":
                responded = True
                print(f"GOT_IT response received from {recv_id}")

    except Exception:
        pass  # ignore failures silently to simulate realistic network unreliability

def wait_for_response(timeout=3):
        global responded
        start = time.time()
        while time.time() - start < timeout:
            if responded:
                return True
            time.sleep(0.1)
        return False

# ==============================
# ELECTION LOGIC
# ==============================
def start_election():
    """Start the Bully election algorithm."""

    global ELECTION_ACTIVE, LEADER, responded

    with LOCK:
        if ELECTION_ACTIVE or IS_FAILED:
            return
        ELECTION_ACTIVE = True

    print(f"[{NODE_ID}] Starting election...")

    higher_nodes = get_higher_nodes(NODE_ID)
    print("Higher nodes:", higher_nodes)

    if not higher_nodes:
        announce_leader()
        ELECTION_ACTIVE = False
        return

    for pid in higher_nodes:
        addr = PEERS[pid]
        print("Sending ELECTION to", pid, addr)
        send_message((NODE_ID, pid), ("ELECTION", PEERS))

    # Check if any higher node responded
    got_response = wait_for_response()

    if not got_response:
        announce_leader()
    else:
        print(f"[{NODE_ID}] Higher node exists; waiting for leader announcement...")
        responded = False  # reset for next election

    with LOCK:
        ELECTION_ACTIVE = False

def announce_leader():
    """Announce self as leader."""
    global LEADER
    LEADER = NODE_ID
    safe_print(f"[{NODE_ID}] I am the new LEADER!")
    for pid, addr in PEERS.items():
        if pid != NODE_ID:
            safe_print(f"[{NODE_ID}] Announcing leadership to {pid}")
            send_message((NODE_ID, pid), ("LEADER", PEERS))

# ==============================
# MESSAGE HANDLER
# ==============================
def handle_message(message, self):
    """Handle all incoming message types."""

    global LEADER, IS_FAILED
    global PEERS

    actual_message, communication = message

    msg_type, peers = actual_message
    from_addr, to_aadr = communication

    print(f"[{NODE_ID}] Received {msg_type} message from {from_addr}")
    PEERS = update_peers(peers)

    if IS_FAILED:
        return  # ignore all messages when feigning failure

    if msg_type == "ELECTION":
        print(f" \n Election message received from {from_addr} \n")
        print(f"\n Going to respond with GOT_IT to {from_addr}\n")
        self.request.sendall(pickle.dumps("GOT_IT"))
        start_election()

    elif msg_type == "LEADER":
        print(f" \n Leader message received from {from_addr} \n")
        LEADER = from_addr
        safe_print(f"[{NODE_ID}] Recognized {LEADER} as leader")

    elif msg_type == "PROBE":
        print(f"\n Probe message received from {from_addr} \n")
        print(f"\n Going to respond with GOT_IT to {from_addr}\n")
        self.request.sendall(pickle.dumps("GOT_IT"))

    else:
        safe_print(f"[{NODE_ID}] Unknown message: {msg_type}")

# ==============================
# SERVER HANDLER
# ==============================
class NodeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw = self.request.recv(BUF_SZ)
        try:
            message = pickle.loads(raw)
            handle_message(message, self)
        except Exception:
            pass

def start_server(host, port):
    """Start threaded server for incoming messages."""
    global SERVER
    SERVER = socketserver.ThreadingTCPServer((host, port), NodeHandler)
    thread = threading.Thread(target=SERVER.serve_forever, daemon=True)
    thread.start()
    return SERVER

# ==============================
# GCD REGISTRATION
# ==============================
def register_with_gcd(days_to_bd, su_id, host, port):
    msg = ("HOWDY", ((days_to_bd, su_id), (host, port)))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((GCD_HOST, GCD_PORT))
            s.sendall(pickle.dumps(msg))
            data = s.recv(BUF_SZ)
            peers = pickle.loads(data)
            safe_print(f"[{NODE_ID}] Registered with GCD. Peers: {list(peers.keys())}")
            return peers
    except Exception as e:
        safe_print(f"[{NODE_ID}] Registration failed: {e}")
        sys.exit(1)

# ==============================
# EXTRA CREDIT: PROBE
# ==============================
def probe_leader():
    """Periodically probe leader to detect failures."""

    global LEADER, PEERS, IS_FAILED, responded

    while True:
        if IS_FAILED:
            time.sleep(2)
            continue

        if LEADER and LEADER != NODE_ID:
            addr = PEERS.get(LEADER)
            if addr:
                send_message((NODE_ID, LEADER), ("PROBE", PEERS))
                responded = wait_for_response()
                if not responded:
                    safe_print(f"[{NODE_ID}] Leader {LEADER} unresponsive! Connecting with GCD and Starting election...")
                    PEERS = update_peers(register_with_gcd(NODE_ID[0], NODE_ID[1], "localhost", LISTENER[1]))
                    start_election()
                else:
                    responded = False  # reset for next probe
        time.sleep(random.uniform(*PROBE_INTERVAL_RANGE))

# ==============================
# EXTRA CREDIT: FAKE FAILURE
# ==============================
def simulate_failure():
    """Simulate random failure and recovery."""
    global IS_FAILED
    while True:
        time_to_fail = random.uniform(*FAIL_INTERVAL_RANGE)
        time.sleep(time_to_fail)
        IS_FAILED = True
        safe_print(f"[{NODE_ID}] Simulating FAILURE for a bit...")
        time.sleep(random.uniform(*FAIL_DURATION_RANGE))
        IS_FAILED = False
        safe_print(f"[{NODE_ID}] Recovered, rejoining network...")
        register_with_gcd(NODE_ID[0], NODE_ID[1], "localhost", LISTENER[1])
        start_election()

# ==============================
# MAIN
# ==============================
def main():
    global NODE_ID, LISTENER, PEERS

    if len(sys.argv) != 4:
        print("Usage: python3 lab2.py <days_to_birthday> <su_id> <port>")
        sys.exit(1)

    days_to_bd = int(sys.argv[1])
    su_id = int(sys.argv[2])
    port = int(sys.argv[3])

    NODE_ID = (days_to_bd, su_id)
    LISTENER = ("localhost", port)

    print(f"Node {NODE_ID} starting on port {port}...")

    start_server("localhost", port)

    PEERS = register_with_gcd(days_to_bd, su_id, "localhost", port)
    print("Peers are: ", PEERS)

    # Start background threads
    threading.Thread(target=probe_leader, daemon=True).start()
    #threading.Thread(target=simulate_failure, daemon=True).start()

    # Start first election
    time.sleep(random.uniform(1, 3))
    start_election()

    # Keep alive
    while True:
        time.sleep(2)

if __name__ == "__main__":
    main()