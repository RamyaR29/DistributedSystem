"""
CPSC 5520, Seattle University
This is free and unencumbered software released into the public domain.
:Authors: Kevin Lundeen
:Version: f19-02
"""
import socket
import pickle

class Node(object):
    """
    Nodes of the calculator abstract syntax tree (AST) for holding an expression to evaluate.
    """

    def __init__(self, op=None, left=None, right=None, leaf=None):
        if (leaf is not None) != ((op is None) and (left is None) and (right is None)):
            raise ValueError('construct an ExpressionTree node as a leaf OR as an interior node')
        self.leaf = leaf
        self.op = op
        self.left = left
        self.right = right


class Calc(object):
    functions = {'+': (lambda x, y: x + y),
                 '-': (lambda x, y: x - y),
                 '*': (lambda x, y: x * y),
                 '/': (lambda x, y: x // y)}

    @staticmethod
    def evaluate(tree):
        """
        Evaluate the given AST.

        :param tree: AST to evaluate
        :return: result of evaluation
        """
        if tree.leaf is not None:
            return tree.leaf
        else:
            f = Calc.functions[tree.op]  # look up the function for this operator
            return f(Calc.evaluate(tree.left), Calc.evaluate(tree.right))

    @staticmethod
    def serve(address):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(address)
            listener.listen(5)
            print('listening for ASTs on {}'.format(listener.getsockname()))
            while True:
                client, client_addr = listener.accept()
                with client:
                    ast = pickle.loads(client.recv(4096))
                    client.sendall(pickle.dumps(Calc.evaluate(ast)))


if __name__ == '__main__':
    Calc.serve(('localhost', 0xBAD3))
