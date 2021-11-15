import pickle
import threading
import socket
import os
import sys
import random
import time
import hashlib

M = 3  # FIXME: Test environment, normally = hashlib.sha1().digest_size * 8
NODES = 2 ** M
BUF_SZ = 4096  # socket recv arg
BACKLOG = 100  # socket listen arg
TEST_BASE = 43544  # for testing use port numbers on localhost at TEST_BASE+n

POSSIBLE_PORTS = range (2**16)


class ChordNode(object):
    def __init__(self, n):

        # n is port number trying to connect to

        print("incoming N: {}".format(n))
        n = int(n)
        # passed in hash already??? #FIXME
        # number 1 - 2^m -1
        self.node = n
        # Initialize finger table/predecessor, successor, and keys
        # indexing starts at 1

        node_id = chord.lookup_node(('localhost', n))

        self.finger = [None] + [FingerEntry(node_id, k) for k in range(1, M+1)]

        self.predecessor = None
        self.successor = None
        self.keys = {}

        # IP is local host
        self.ip_address = "127.0.0.1"

        # find an empty port. Find port mapped to node id n
        self.port = self.get_open_port(node_id)

        # Peer address for our node, trying to join network
        self.full_address = (self.ip_address, self.port)

        self.key_identifier = None     # hash of the key? Whats the fucking key?

        self.socket = socket.socket()

        self.join(n)

    def join(self, port_number):
        print("trying to join up")

        validator_address = ('localhost', port_number)

        if port_number == 0:
            print("New network being created.")
            print("Peer: {} joined the network".format(self.full_address))
            self.start_server()
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as validator_node:
                    validator_node.settimeout(1.5)
                    validator_node.connect(validator_address)
                    self.init_fingerTable(validator_node)
                    # initialize finger table

            except Exception as e:
                print("FAILED: {}".format(e))




    def get_open_port(self, n):
        possible_ports = CHORD_MAP[n]
        for port in possible_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    connected = s.connect_ex( ('localhost', port) )
                    if connected:
                        s.close()
                        return port
                    else:
                        s.close()
            except Exception as e:
                print("Couldn't connect to port {} because it was in use."
                      " \nError: {}".format(port, e))


    def start_server(self):
        self.socket.bind(self.full_address)
        thread = threading.Thread(target=self.start_listening,
                                       args=(self.socket,))
        thread.start()

    def start_listening(self, listening_socket):
        listening_socket.listen(5)
        print("Socket is listening ... ")
        while True:
            client, address = listening_socket.accept()
            print("Request from {}".format(address))
            thread = threading.Thread(target=self.handle_rpc,
                                      args=(client, address))
            thread.start()
            time.sleep(0.1)

    @staticmethod
    def call_rpc(target_node, message):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            s.settimeout(1.5)
            s.connect(target_node) #connect to nodes address
            # send entire buffer and serialize a HELLO msg for server
            s.sendall(pickle.dumps(message))

    def handle_rpc(self, client, address):

        # recieve message from client
        message_rpc = client.recv(BUF_SZ)

        # unpickle the message
        message = pickle.loads(message_rpc)

        # Default argument values
        arg1 = None
        arg2 = None

        # decompose the message
        if len(message == 1):
            method = message[0]
        elif len(message == 2):
            method = message[0]
            arg1 = message[1]
        else:
            method = message[0]
            arg1 = message[1]
            arg2 = message[2]

        # pass to function handler
        result = self.dispatch(method, arg1, arg2)

        # send back result
        client.sendall(pickle.dumps(result))
        print("message")
        client.close()

    def dispatch(self, method, arg1=None, arg2=None):

        if method == 'FIND_SUCCESSOR':
            return self.find_successor(arg1)
        elif method == 'GET_SUCCESSOR':
            print("called get_successor")
            return self.successor
        else:
            print("another fn")

    @property
    def successor(self):
        return self.finger[1].node

    @successor.setter
    def successor(self, id):
        self.finger[1].node = id

    def find_successor(self, id):
        """ Ask this node to find id's successor = successor(predecessor(id))"""
        np = self.find_predecessor(id)

        # np has to be an address at this point or this won't work

        # is np going to be a chord node or node identifier???
        return self.call_rpc(np, 'GET_SUCCESSOR')

    def find_predecessor(self, id):
        np = self.node

        # np_id is the numerical number associated with the node
        while id not in range(np+1, self.successor + 1):
            np = self.closest_preceding_finger(id)

        return np
    def closest_preceding_finger(self, id):
        print("get neighbor")
        """
        :param id: the parameter id to find the closest preceding node to
        :return: return Key class type
        """
        for i in range(M, 1, -1) : #4,3,2,1,0
            if self.finger[i] in range(self.node + 1, id -1):
                return self.finger[i]

    def init_fingerTable(self, validator_node):
        print("Attempting to initialize finger "
              "tables of new node: {}".format(self.node))

        # n' id
        validator_id = chord.lookup_node(validator_node)
        message = ['FIND_SUCCESSOR', validator_id]

        successor = validator_node.sendall(pickle.dumps(message))
        self.finger[0] = successor


class ModRange(object):

    def __init__(self, start, stop, divisor):
        self.divisor = divisor
        self.start = start % self.divisor
        self.stop = stop % self.divisor
        # we want to use ranges to make things speedy, but if it wraps around the 0 node, we have to use two
        if self.start < self.stop:
            self.intervals = (range(self.start, self.stop),)
        elif self.stop == 0:
            self.intervals = (range(self.start, self.divisor),)
        else:
            self.intervals = (
            range(self.start, self.divisor), range(0, self.stop))

    def __repr__(self):
        """ Something like the interval|node charts in the paper """
        return ''.format(self.start, self.stop, self.divisor)

    def __contains__(self, id):
        """ Is the given id within this finger's interval? """
        for interval in self.intervals:
            if id in interval:
                return True
        return False

    def __len__(self):
        total = 0
        for interval in self.intervals:
            total += len(interval)
        return total

    def __iter__(self):
        return ModRangeIter(self, 0, -1)

class ModRangeIter(object):
    """ Iterator class for ModRange """

    def __init__(self, mr, i, j):
        self.mr, self.i, self.j = mr, i, j

    def __iter__(self):
        return ModRangeIter(self.mr, self.i, self.j)

    def __next__(self):
        if self.j == len(self.mr.intervals[self.i]) - 1:
            if self.i == len(self.mr.intervals) - 1:
                raise StopIteration()
            else:
                self.i += 1
                self.j = 0
        else:
            self.j += 1
        return self.mr.intervals[self.i][self.j]

class FingerEntry(object):

    def __init__(self, n, k, node=None):
        if not (0 <= n < NODES and 0 < k <= M):
            raise ValueError('invalid finger entry values')
        self.start = (n + 2 ** (k - 1)) % NODES
        self.next_start = (n + 2 ** k) % NODES if k < M else n
        self.interval = ModRange(self.start, self.next_start, NODES)
        self.node = node

    def __repr__(self):
        """ Something like the interval|node charts in the paper """
        return ''.format(self.start, self.next_start, self.node)

    def __contains__(self, id):
        """ Is the given id within this finger's interval? """
        return id in self.interval


PORTS = range(64888, 65535)

class Chord(object):
    def __init__(self):
        self.node_map = {}

    def lookup_node(self, node_address):
        # are node addresses keys??

        address_bytesObj = pickle.dumps(node_address)

        # Push identifier through hash function
        marshalled_hash = hashlib.sha1(address_bytesObj).digest()

        # generate corresponding node from hash
        node_id = int.from_bytes(marshalled_hash, byteorder='big') % NODES

        return node_id
    def generateChordMap(self):

        # create up to 2^m - 1 node ids
        node_ids = range(NODES)
        for node_id in node_ids:
            self.node_map[node_id] = []

        for port in PORTS:
            # For given port and ip what is the correspond node id
            node = self.lookup_node(('localhost', port))
            self.node_map[node].append(port)

        return self.node_map

    def __str__(self):
        return self.node_map.__str__()


chord = Chord()
CHORD_MAP = chord.generateChordMap()

if __name__ == '__main__':

    args = sys.argv
    peer = ChordNode(args[1])

    #run peer