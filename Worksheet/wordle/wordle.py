import socket
import pickle

ENGLISH_WORDS = '/usr/share/dict/words'
RPC_PORT = 10011

def starts_with(prefix, letters=5):
    sz = len(prefix)
    ret = []
    with open(ENGLISH_WORDS, 'r') as words:
        for word in words:
            word = word.strip() # remove trailing newline
            if word[:sz] == prefix and len(word) == letters:
                ret.append(word)
    return ret

if __name__ == '__main__':
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:
        serv.bind(('', RPC_PORT))
        serv.listen(1)
        while True:
            client, _whom = serv.accept()
            request = pickle.loads(client.recv(4096))
            print('LOG: got request', request)
            # FIXME - finish marshalling...!
            if request[0] == 'starts_with':
                prefix = request[1]
                if len(request) == 2:
                    result = starts_with(prefix)
                else:
                    letters = request[2]
                    result = starts_with(prefix, prefix, letters)
                client.sendall(pickle.dumps(result))
            else:
                client.sendall(b'I got your request but it is bad')
            client.close()
