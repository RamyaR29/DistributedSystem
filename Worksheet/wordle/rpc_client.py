import socket
import pickle

from wordle import RPC_PORT

RPC_HOST = 'cs1.seattleu.edu'
BUF_SIZE = 1024

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.connect((RPC_HOST, RPC_PORT))
        while True:
            prefix = input('Enter a prefix: ')
            server.sendall(pickle.dumps(('starts_with', prefix)))
            answer = pickle.loads(server.recv(BUF_SIZE))
            print(answer)

if __name__ == '__main__':
    main()