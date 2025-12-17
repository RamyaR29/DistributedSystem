# lab3.py
# Seattle University CPSC 5520 - Lab 3: Currency Arbitrage Detection (Subscriber)
# Author: Ramya Ramesh
# Works with: forex_provider.py, fxp_bytes_subscriber.py, bellman_ford.py

import socket
import time
import math
from datetime import datetime
from fxp_bytes_subscriber import make_request, decode_message
from bellman_ford import BellmanFord


class QuoteManager:
    """Manages live forex quotes and builds a Bellman-Ford graph."""
    def __init__(self, timeout=10):
        self.quotes = {}  # {(c1, c2): (rate, timestamp_micro)}
        self.latest_timestamp = 0.0
        self.timeout = timeout

    def add_quote(self, c1, c2, rate, ts_micro):
        """Add a new quote if it's not out-of-sequence."""
        if ts_micro < self.latest_timestamp:
            ts_str = datetime.fromtimestamp(ts_micro / 1_000_000.0)
            print(f"{ts_str} {c1} {c2} {rate}")
            print("ignoring out-of-sequence message")
            return False

        self.quotes[(c1, c2)] = (rate, ts_micro)
        self.latest_timestamp = max(self.latest_timestamp, ts_micro)
        return True

    def remove_stale_quotes(self):
        """Remove quotes older than timeout seconds."""
        now = time.time()
        to_remove = []
        for (c1, c2), (_, ts_micro) in self.quotes.items():
            ts = ts_micro / 1_000_000.0
            if now - ts > self.timeout:
                print(f"removing stale quote for ({c1!r}, {c2!r})")
                to_remove.append((c1, c2))
        for key in to_remove:
            del self.quotes[key]

    def print_quotes(self):
        """Print all quotes sorted by timestamp."""
        sorted_q = sorted(self.quotes.items(), key=lambda kv: kv[1][1])
        for (c1, c2), (rate, ts_micro) in sorted_q:
            ts_str = datetime.fromtimestamp(ts_micro / 1_000_000.0)
            print(f"{ts_str} {c1} {c2} {rate}")

    def build_graph(self):
        """Create a Bellman-Ford graph from current quotes."""
        bf = BellmanFord()
        for (c1, c2), (rate, _) in self.quotes.items():
            bf.add_edge(c1, c2, -math.log(rate))
        return bf


class ArbitrageDetector:
    """Detects and reconstructs arbitrage cycles using Bellman-Ford."""
    def __init__(self, quote_manager):
        self.qm = quote_manager

    def detect(self, start_amount=100.0):
        """Return a list of arbitrage sequences found."""
        results = []
        bf = self.qm.build_graph()

        for node in bf.vertices:
            dist, pred, neg_edge = bf.shortest_paths(node,0)
            if not neg_edge:
                continue

            # reconstruct negative cycle
            u, v = neg_edge
            cycle, visited = [], set()
            current = v
            while current not in visited:
                visited.add(current)
                cycle.append(current)
                current = pred[current] if pred[current] is not None else u
            cycle.append(current)
            cycle.reverse()

            # compute currency conversion along the cycle
            amounts = [start_amount]
            for i in range(len(cycle) - 1):
                c_from, c_to = cycle[i], cycle[i + 1]
                if (c_from, c_to) not in self.qm.quotes:
                    break
                rate, _ = self.qm.quotes[(c_from, c_to)]
                amounts.append(amounts[-1] * rate)

            sequence = list(zip(cycle, amounts))
            results.append(sequence)

        return results

    def print_arbitrages(self, sequences):
        """Print arbitrage opportunities in the required format."""
        for seq in sequences:
            print("ARBITRAGE:")
            print(f"\tstart with {seq[0][0]} {int(seq[0][1])}")
            for i in range(len(seq) - 1):
                c_from, amt_from = seq[i]
                c_to, amt_to = seq[i + 1]
                rate = amt_to / amt_from
                print(f"\texchange {c_from} for {c_to} at {rate} --> {c_to} {amt_to}")
            print()


class ForexSubscriber:
    """Subscribes to forex updates and detects arbitrage."""
    def __init__(self, provider_ip="127.0.0.1", provider_port=50403, subscriber_port=12000, run_minutes=10):
        self.provider_ip = provider_ip
        self.provider_port = provider_port
        self.subscriber_port = subscriber_port
        self.run_duration = run_minutes * 60  # convert to seconds
        self.pub_silence_time = 60  # seconds
        self.qm = QuoteManager()
        self.detector = ArbitrageDetector(self.qm)

    def run(self):
        """Main loop for receiving quotes and detecting arbitrage."""
        provider_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        subscriber_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        subscriber_sock.bind(("", self.subscriber_port))
        subscriber_sock.settimeout(600.0)

        msg = make_request(self.provider_ip, self.subscriber_port)
        provider_sock.sendto(msg, (self.provider_ip, self.provider_port))
        print(f"Subscribed to Forex Provider at ({self.provider_ip}, {self.provider_port})")

        start_time = time.time()

        try:
            while True:
                if time.time() - start_time > self.run_duration:
                    print("10 minutes elapsed. Closing subscriber.")
                    break

                try:
                    data, _ = subscriber_sock.recvfrom(2048)
                    last_msg_time = time.time()  # message received successfully
                except socket.timeout:
                    # --- Check for inactivity (1 min without message) ---
                    if time.time() - last_msg_time > self.pub_silence_time:
                        print("No messages received for over 1 minute. Shutting down.")
                        break
                    continue

                records = decode_message(data)

                for c1, c2, rate, ts_micro in records:
                    self.qm.add_quote(c1, c2, rate, ts_micro)

                self.qm.remove_stale_quotes()
                self.qm.print_quotes()

                sequences = self.detector.detect(start_amount=100.0)
                self.detector.print_arbitrages(sequences)

                time.sleep(1)

        except KeyboardInterrupt:
            print("\nSubscriber stopped.")
        finally:
            subscriber_sock.close()
            provider_sock.close()


if __name__ == "__main__":
    ForexSubscriber().run()