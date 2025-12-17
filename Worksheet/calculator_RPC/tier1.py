"""
CPSC 5520, Seattle University
This is free and unencumbered software released into the public domain.
:Authors: Kevin Lundeen
:Version: f19-02
"""


import socket
import pickle
from tier2 import RPC_PORT

RPC_HOST = 'localhost'
BUF_SIZE = 4096
# client side

def compute(expression):
        """
        Parse and evaluate the given expression.

        :param expression: string expression to compute
        :return: the answer
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((RPC_HOST, 10011))
            while True:
                client.sendall(pickle.dumps(expression))
                answer = pickle.loads(client.recv(BUF_SIZE))
                return answer


if __name__ == '__main__':
    test = '( 3 + 7 ) * ( 11 - 2 / 2 )'  # remember to put spaces around everything including parentheses!
    print(test, '=', compute(test))
