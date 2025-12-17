# Simple client for Group Coordinator Daemon (GCD)
# Written in Python 3
#
# Usage:
#   python3 lab1.py HOST PORT
#
# Example:
#   python3 lab1.py cs2.seattleu.edu 23600

import socket
import sys
import pickle

"""
lab1.py
Client for Group Coordinator Daemon (GCD).
Connects to the GCD, retrieves group members, sends BEGIN to each.
"""
def main():
    #Validate args
    if len(sys.argv) != 3:
        print("Provide Args - Eg: python3 lab1.py HOST PORT")
        sys.exit(1)

    hostToContact = sys.argv[1]
    portNumber = int(sys.argv[2])

    #Contact GCD
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as gcdConnect:
            gcdConnect.connect((hostToContact, portNumber))
            print("BEGIN", (hostToContact, portNumber))
            
            gcdConnect.sendall(pickle.dumps("HOWDY"))

            rawdata = gcdConnect.recv(5000)
            memberpair = pickle.loads(rawdata)

    except Exception as e:
        print("Failed to connect to the GCD:", e)
        sys.exit(1)

    #Contact each group member
    for pair in memberpair:
        print("HELLO to", pair)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer:
                peer.settimeout(1.5)
                peer.connect((pair['host'], pair['port']))

                # Send BEGIN
                peer.sendall(pickle.dumps("BEGIN"))

                # Receive reply
                reply = peer.recv(5000)
                response = pickle.loads(reply)

                print(response)

        except Exception as e:
            print("failed to connect:", pair, e)

if __name__ == "__main__":
    main()