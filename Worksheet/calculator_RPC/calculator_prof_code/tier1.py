"""
CPSC 5520, Seattle University
This is free and unencumbered software released into the public domain.
:Authors: Kevin Lundeen
:Version: f19-02
"""
import socket
import pickle

class Calc(object):
    tier2_address = ('localhost', 0xBAD2)

    @staticmethod
    def compute(expression):
        """
        Parse and evaluate the given expression.

        :param expression: string expression to compute
        :return: the answer
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as requester:
            requester.connect(Calc.tier2_address)
            requester.sendall(pickle.dumps(expression))
            return pickle.loads(requester.recv(4096))

if __name__ == '__main__':
    test = '( 3 + 7 ) * ( 11 - 2 / 2 )'  # remember to put spaces around everything including parentheses!
    print(test, '=', Calc.compute(test))
