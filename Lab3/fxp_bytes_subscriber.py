# fxp_bytes_subscriber.py
# Matches structure of fxp_bytes.py (4 functions)
# Used by subscriber to communicate with forex_provider

import socket
import struct

# make_request — same role name as fxp_bytes, but used to send subscription info
def make_request(ip_str: str, port: int) -> bytes:
    """
    Create a subscription request message.
    Format: 4 bytes IP + 2 bytes port (network byte order)
    """
    ip_bytes = socket.inet_aton(ip_str)
    port_bytes = struct.pack("!H", port)
    return ip_bytes + port_bytes


# extract_ip_port — reverse of make_request
def extract_ip_port(data: bytes):
    """
    Extract (ip, port) tuple from a subscription request message.
    """
    if len(data) < 6:
        raise ValueError("Invalid subscription message length")
    ip_bytes = data[:4]
    port_bytes = data[4:6]
    ip_str = socket.inet_ntoa(ip_bytes)
    port = struct.unpack("!H", port_bytes)[0]
    return ip_str, port


# decode_message — used by subscriber to parse incoming forex quote packets
def decode_message(data: bytes):
    """
    Decode incoming forex quote messages.
    Each record: 3-byte c1 + 3-byte c2 + 4-byte float (rate) + 8-byte timestamp (microseconds)
    """
    records = []
    record_size = 32  # instructor’s spec uses padded 32 bytes per quote
    for i in range(0, len(data), record_size):
        rec = data[i:i + record_size]
        if len(rec) < record_size:
            continue
        c1 = rec[0:3].decode("ascii").strip("\x00")
        c2 = rec[3:6].decode("ascii").strip("\x00")
        rate = struct.unpack("<f", rec[6:10])[0]
        timestamp = struct.unpack("!Q", rec[10:18])[0]
        records.append((c1, c2, rate, timestamp))
    return records


# encode_ack — optional, mirrors fxp_bytes.encode_message but for subscriber acknowledgements
def encode_ack(ip_str: str, port: int) -> bytes:
    """
    (Optional) Encode a simple acknowledgment message to send back to the provider.
    Not used in basic lab, but keeps structure parallel to fxp_bytes.py
    """
    ip_bytes = socket.inet_aton(ip_str)
    port_bytes = struct.pack("!H", port)
    return b"ACK" + ip_bytes + port_bytes