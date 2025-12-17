"""
CPSC 5520, Seattle University
This is free and unencumbered software released into the public domain.
:Authors: Kevin Lundeen
:Version: f19-02
"""


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

    def __repr__(self):
        if self.leaf is not None:
            return str(self.leaf)
        else:
            return '({}{}{})'.format(self.left, self.op, self.right)


class Calc(object):
    operators = {'+': 1, '-': 1, '*': 2, '/': 2}  # value is the precedence; all assumed left-associative
    functions = {'+': (lambda x, y: x + y),
                 '-': (lambda x, y: x - y),
                 '*': (lambda x, y: x * y),
                 '/': (lambda x, y: x // y)}

    @staticmethod
    def parse(expression):
        """
        Parses a simple infix integer expression with only binary operators and parentheses.
        All tokens must be separated by whitespace since we are just using str.split() for a lexer.
        Respects standard operator precedence and parenthesized expressions.

        :param expression: expression to parse, e.g., '( 3 + 7 ) * ( 11 - 2 / 2 )' --> 100
        :return: abstract syntax tree of the expression
        """

        # ### helper nested functions: empty, peek, pop, push, build, precedes, error ###
        def empty():
            """Is op_stack empty?"""
            return len(op_stack) == 0

        def peek():
            """Gets top operator from op_stack."""
            if len(op_stack) == 0:
                error('missing operator or parens')
            return op_stack[-1]

        def pop():
            """Pops top operator from op_stack."""
            return op_stack.pop()

        def push():
            """Pushes an operator or left paren onto op_stack"""
            op_stack.append(token)

        def build(leaf=None):
            """Build next AST Node and push onto ast_stack."""
            if leaf is None:
                if len(ast_stack) < 2:
                    error('missing operand')
                right = ast_stack.pop()
                left = ast_stack.pop()
                ast_stack.append(Node(op_stack.pop(), left, right))
            else:
                ast_stack.append(Node(leaf=leaf))
            # print(ast_stack)

        def precedes(left_op, right_op):
            """Should left_op precede right_op in normal precedence?"""
            return Calc.operators[left_op] >= Calc.operators[right_op]

        def error(explanation):
            """Raise a parse exception!"""
            raise ValueError('invalid expression - {} noticed around {}'.format(explanation, token))

        # ### end of nested functions for parse() ###

        op_stack = []
        ast_stack = []
        for token in expression.split():  # FIXME: split() is a really lame lexical analyzer
            try:
                build(int(token))  # will raise ValueError if not a number
            except ValueError:
                if token in Calc.operators:  # flush out all higher or equal precedence operations, then remember token
                    while not empty() and peek() != '(' and precedes(peek(), token):
                        build()
                    push()
                elif token == '(':  # mark where the parenthetical starts
                    push()
                elif token == ')':  # flush out back to beginning of this parenthetical
                    while peek() != '(':
                        build()
                    pop()
                else:
                    error('unknown operator')
        while not empty():  # flush out remaining operators
            build()
        if len(ast_stack) != 1:  # one last check -- should just be the one final AST
            error('too many/few subexpressions')
        return ast_stack.pop()

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
    def compute(expression):
        """
        Parse and evaluate the given expression.

        :param expression: string expression to compute
        :return: the answer
        """
        return Calc.evaluate(Calc.parse(expression))


if __name__ == '__main__':
    test = '( 3 + 7 ) * ( 11 - 2 / 2 )'  # remember to put spaces around everything including parentheses!
    print(test, '=', Calc.compute(test))
