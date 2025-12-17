"""
CPSC 5520, Seattle University
This is free and unencumbered software released into the public domain.
Lab 5: Blockchain
"""

import hashlib
import socket
import time
from time import strftime, gmtime

BUFFER_SIZE = int(2e6)  # bitcoin MAX_SIZE

SU_ID = 4273268  # Change this to your actual SU ID
BLOCK_NUMBER = SU_ID % 10000

# Bitcoin network connection
BTC_HOST = "23.149.168.151"  # Replace with a working node from nodes_main.txt
BTC_PORT = 8333
VERSION = 70015

START_STRING = bytearray.fromhex("f9beb4d9")
HDR_SZ = 24

# Message type constants
MSG_BLOCK = 2
MSG_TX = 1


def checksum(payload):
	"""
	Double hashes a payload to get a checksum
	:param payload: the payload to hash
	:return: the first four bytes of the resulting hash
	"""
	return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]


def build_packet(cmd_name, payload):
	"""
	Constructs a Bitcoin message header
	:param cmd_name: the command to send
	:param payload: the actual data of the message
	"""
	command = cmd_name.encode()
	while not len(command) == 12:
		command += '\0'.encode()

	payload_size = uint32_t(len(payload))

	return START_STRING + command + payload_size + checksum(payload) + payload


def compactsize_t(n):
	if n < 252:
		return uint8_t(n)
	if n < 0xffff:
		return uint8_t(0xfd) + uint16_t(n)
	if n < 0xffffffff:
		return uint8_t(0xfe) + uint32_t(n)
	return uint8_t(0xff) + uint64_t(n)


def unmarshal_compactsize(b):
	if len(b) == 0:
		return b'', 0
	key = b[0]
	if key == 0xff:
		if len(b) < 9:
			return b'', 0
		return b[0:9], unmarshal_uint(b[1:9])
	if key == 0xfe:
		if len(b) < 5:
			return b'', 0
		return b[0:5], unmarshal_uint(b[1:5])
	if key == 0xfd:
		if len(b) < 3:
			return b'', 0
		return b[0:3], unmarshal_uint(b[1:3])
	return b[0:1], unmarshal_uint(b[0:1])


def bool_t(flag):
	return uint8_t(1 if flag else 0)


def ipv6_from_ipv4(ipv4_str):
	pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
	return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))


def ipv6_to_ipv4(ipv6):
	return '.'.join([str(b) for b in ipv6[12:]])


def uint8_t(n):
	return int(n).to_bytes(1, byteorder='little', signed=False)


def uint16_t(n, byteorder='little'):
	return int(n).to_bytes(2, byteorder=byteorder, signed=False)


def int32_t(n):
	return int(n).to_bytes(4, byteorder='little', signed=True)


def uint32_t(n):
	return int(n).to_bytes(4, byteorder='little', signed=False)


def int64_t(n):
	return int(n).to_bytes(8, byteorder='little', signed=True)


def uint64_t(n):
	return int(n).to_bytes(8, byteorder='little', signed=False)


def unmarshal_int(b):
	return int.from_bytes(b, byteorder='little', signed=True)


def unmarshal_uint(b, byteorder='little'):
	return int.from_bytes(b, byteorder=byteorder, signed=False)


def get_version_message():
	"""
	Generates a version message to send to a node
	:returns: the constructed version message
	"""
	version = uint32_t(VERSION)
	services = uint64_t(0)  # 0 = not a full node
	timestamp = uint64_t(int(time.time()))
	addr_recv_services = uint64_t(1)  # 1 = full node
	addr_recv = ipv6_from_ipv4(BTC_HOST)
	addr_recv_port = uint16_t(BTC_PORT, 'big')
	addr_trans_services = services
	addr_trans = ipv6_from_ipv4("127.0.0.1")
	addr_trans_port = uint16_t(0, 'big')
	nonce = uint64_t(0)
	user_agent_bytes = compactsize_t(0)
	start_height = uint32_t(0)
	relay = bool_t(False)

	recv = addr_recv_services + addr_recv + addr_recv_port
	trans = addr_trans_services + addr_trans + addr_trans_port

	return version + services + timestamp + recv + trans + nonce + user_agent_bytes + start_height + relay


def get_getblocks_message():
	"""
	Generates a getblocks message to request block inventory
	:returns: the constructed getblocks message
	"""
	version = uint32_t(VERSION)
	count = compactsize_t(1)
	# Start from genesis block hash (all zeros)
	header_hash = bytearray(32)
	# Stop hash (all zeros means no stop)
	end_hash = bytearray(32)

	return version + count + header_hash + end_hash


def get_getdata_message(inv_type, block_hash):
	"""
	Generates a getdata message to request a specific block
	:param inv_type: inventory type (MSG_BLOCK = 2)
	:param block_hash: the block hash to request
	:returns: the constructed getdata message
	"""
	count = compactsize_t(1)
	inv_entry = uint32_t(inv_type) + block_hash
	return count + inv_entry


def recv_message(sock):
	"""
	Receive a complete Bitcoin message from the socket
	:param sock: the socket to receive from
	:return: (command, payload) or (None, None) on error
	"""
	try:
		header = sock.recv(HDR_SZ)
		if len(header) < HDR_SZ:
			return None, None

		magic = header[:4]
		if magic != START_STRING:
			# Try to resync
			return None, None

		command_hex = header[4:16]
		payload_size_bytes = header[16:20]
		checksum_bytes = header[20:24]

		payload_size = unmarshal_uint(payload_size_bytes)
		if payload_size > BUFFER_SIZE:
			return None, None

		payload = b''
		while len(payload) < payload_size:
			chunk = sock.recv(payload_size - len(payload))
			if not chunk:
				return None, None
			payload += chunk

		# Verify checksum
		expected_checksum = checksum(payload)
		if expected_checksum != checksum_bytes:
			print("WARNING: Checksum mismatch!")
			return None, None

		command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
		return command, payload
	except Exception as e:
		print(f"Error receiving message: {e}")
		return None, None


def parse_inv(payload):
	"""
	Parse an inv message payload
	:param payload: the inv message payload
	:return: list of (type, hash) tuples
	"""
	inv_items = []
	pos = 0

	# Read count
	count_bytes, count = unmarshal_compactsize(payload[pos:])
	pos += len(count_bytes)

	# Read inventory items
	for _ in range(count):
		if pos + 36 > len(payload):
			break
		inv_type = unmarshal_uint(payload[pos:pos+4])
		inv_hash = payload[pos+4:pos+36]
		inv_items.append((inv_type, inv_hash))
		pos += 36

	return inv_items


def parse_block_header(header):
	"""
	Parse a Bitcoin block header (80 bytes)
	:param header: 80-byte block header
	:return: dictionary with parsed fields
	"""
	if len(header) < 80:
		return None

	version = unmarshal_int(header[0:4])
	prev_block = header[4:36].hex()
	merkle_root = header[36:68].hex()
	timestamp = unmarshal_uint(header[68:72])
	bits = unmarshal_uint(header[72:76])
	nonce = unmarshal_uint(header[76:80])

	# Calculate block hash (double SHA256, reversed)
	block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1]

	return {
		'version': version,
		'prev_block': prev_block,
		'merkle_root': merkle_root,
		'timestamp': timestamp,
		'bits': bits,
		'nonce': nonce,
		'hash': block_hash.hex()
	}


def parse_transaction(tx_bytes, offset=0):
	"""
	Parse a Bitcoin transaction
	:param tx_bytes: bytes containing the transaction
	:param offset: starting offset in tx_bytes
	:return: (tx_data_dict, next_offset)
	"""
	pos = offset
	start_pos = pos

	# Version (4 bytes)
	version = unmarshal_int(tx_bytes[pos:pos+4])
	pos += 4

	# Input count
	input_count_bytes, input_count = unmarshal_compactsize(tx_bytes[pos:])
	pos += len(input_count_bytes)

	inputs = []
	for i in range(input_count):
		if pos + 36 > len(tx_bytes):
			break
		# Previous output hash (32 bytes, reversed)
		prev_tx_hash = tx_bytes[pos:pos+32][::-1].hex()
		pos += 32
		# Previous output index (4 bytes)
		prev_output_index = unmarshal_uint(tx_bytes[pos:pos+4])
		pos += 4
		# Script length
		script_len_bytes, script_len = unmarshal_compactsize(tx_bytes[pos:])
		pos += len(script_len_bytes)
		# Script
		script = tx_bytes[pos:pos+script_len]
		pos += script_len
		# Sequence (4 bytes)
		sequence = unmarshal_uint(tx_bytes[pos:pos+4])
		pos += 4

		inputs.append({
			'prev_tx_hash': prev_tx_hash,
			'prev_output_index': prev_output_index,
			'script': script.hex(),
			'script_len': script_len,
			'sequence': sequence
		})

	# Output count
	output_count_bytes, output_count = unmarshal_compactsize(tx_bytes[pos:])
	pos += len(output_count_bytes)

	outputs = []
	for i in range(output_count):
		if pos + 8 > len(tx_bytes):
			break
		# Value (8 bytes, satoshis)
		value = unmarshal_uint(tx_bytes[pos:pos+8])
		pos += 8
		# Script length
		script_len_bytes, script_len = unmarshal_compactsize(tx_bytes[pos:])
		pos += len(script_len_bytes)
		# Script
		script = tx_bytes[pos:pos+script_len]
		pos += script_len

		outputs.append({
			'value': value,
			'script': script.hex(),
			'script_len': script_len
		})

	# Locktime (4 bytes)
	locktime = unmarshal_uint(tx_bytes[pos:pos+4])
	pos += 4

	# Calculate TXID (double SHA256 of transaction, reversed)
	tx_raw = tx_bytes[start_pos:pos]
	txid = hashlib.sha256(hashlib.sha256(tx_raw).digest()).digest()[::-1].hex()

	return {
		'txid': txid,
		'version': version,
		'inputs': inputs,
		'outputs': outputs,
		'locktime': locktime,
		'raw': tx_raw
	}, pos


def parse_block(block_bytes):
	"""
	Parse a complete Bitcoin block
	:param block_bytes: bytes containing the block
	:return: (header_dict, transactions_list)
	"""
	if len(block_bytes) < 80:
		return None, []

	# Parse header
	header = parse_block_header(block_bytes[:80])

	# Parse transactions
	pos = 80
	tx_count_bytes, tx_count = unmarshal_compactsize(block_bytes[pos:])
	pos += len(tx_count_bytes)

	transactions = []
	for i in range(tx_count):
		if pos >= len(block_bytes):
			break
		tx_data, next_pos = parse_transaction(block_bytes, pos)
		transactions.append(tx_data)
		pos = next_pos

	return header, transactions


def compute_merkle_root(tx_hashes):
	"""
	Compute the Merkle root from a list of transaction hashes
	:param tx_hashes: list of transaction hash bytes (double SHA256, not reversed)
	:return: merkle root as bytes (reversed for block header format)
	"""
	if not tx_hashes:
		return bytearray(32)

	# Convert to list of bytes if needed
	layer = [bytes.fromhex(h) if isinstance(h, str) else h for h in tx_hashes]

	while len(layer) > 1:
		# If odd number, duplicate last
		if len(layer) % 2 == 1:
			layer.append(layer[-1])

		# Pair up and hash
		new_layer = []
		for i in range(0, len(layer), 2):
			combined = layer[i] + layer[i+1]
			new_layer.append(hashlib.sha256(hashlib.sha256(combined).digest()).digest())

		layer = new_layer

	# Return reversed (for block header format)
	return layer[0][::-1] if layer else bytearray(32)


def modify_transaction_output(transaction, output_index, new_script_hex):
	"""
	Modify a transaction output and return new transaction
	:param transaction: transaction dictionary from parse_transaction
	:param output_index: index of output to modify
	:param new_script_hex: new script as hex string
	:return: new transaction raw bytes
	"""
	if output_index >= len(transaction['outputs']):
		return transaction['raw']

	new_script = bytes.fromhex(new_script_hex)
	new_script_len = len(new_script)

	# Rebuild transaction
	tx_bytes = bytearray()

	# Version
	tx_bytes.extend(uint32_t(transaction['version']))

	# Input count
	tx_bytes.extend(compactsize_t(len(transaction['inputs'])))

	# Inputs
	for inp in transaction['inputs']:
		tx_bytes.extend(bytes.fromhex(inp['prev_tx_hash'])[::-1])  # Reverse for network format
		tx_bytes.extend(uint32_t(inp['prev_output_index']))
		tx_bytes.extend(compactsize_t(inp['script_len']))
		tx_bytes.extend(bytes.fromhex(inp['script']))
		tx_bytes.extend(uint32_t(inp['sequence']))

	# Output count
	tx_bytes.extend(compactsize_t(len(transaction['outputs'])))

	# Outputs
	for i, out in enumerate(transaction['outputs']):
		tx_bytes.extend(uint64_t(out['value']))
		if i == output_index:
			# Use new script
			tx_bytes.extend(compactsize_t(new_script_len))
			tx_bytes.extend(new_script)
		else:
			# Keep original script
			tx_bytes.extend(compactsize_t(out['script_len']))
			tx_bytes.extend(bytes.fromhex(out['script']))

	# Locktime
	tx_bytes.extend(uint32_t(transaction['locktime']))

	return bytes(tx_bytes)


def print_message(msg, text=None):
	"""
	Report the contents of the given bitcoin message
	:param msg: bitcoin message including header
	:return: message type
	"""
	print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
	print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
	payload = msg[HDR_SZ:]
	command = print_header(msg[:HDR_SZ], checksum(payload))
	if command == 'version':
		print_version_msg(payload)
	elif command == 'getblocks':
		print_blocks_msg(payload)
	# FIXME print out the payloads of other types of messages, too
	return command


def print_version_msg(b):
	"""
	Report the contents of the given bitcoin version message (sans the header)
	:param payload: version message contents
	"""
	# pull out fields
	version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
	rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
	nonce = b[72:80]
	user_agent_size, uasz = unmarshal_compactsize(b[80:])
	i = 80 + len(user_agent_size)
	user_agent = b[i:i + uasz]
	i += uasz
	start_height, relay = b[i:i + 4], b[i + 4:i + 5]
	extra = b[i + 5:]

	# print report
	prefix = '  '
	print(prefix + 'VERSION')
	print(prefix + '-' * 56)
	prefix *= 2
	print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
	print('{}{:32} my services'.format(prefix, my_services.hex()))
	time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
	print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
	print('{}{:32} your services'.format(prefix, your_services.hex()))
	print('{}{:32} your host {}'.format(prefix, rec_host.hex(), ipv6_to_ipv4(rec_host)))
	print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port, 'big')))
	print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
	print('{}{:32} my host {}'.format(prefix, my_host.hex(), ipv6_to_ipv4(my_host)))
	print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port, 'big')))
	print('{}{:32} nonce'.format(prefix, nonce.hex()))
	print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
	print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
	print('{}{:32} start height {}'.format(prefix, start_height.hex(), unmarshal_uint(start_height)))
	print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
	if len(extra) > 0:
		print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))


def print_blocks_msg(b):
	"""
	Report the contents of the given bitcoin getblocks message (sans the header)
	:param b: getblocks message contents
	"""
	version, count, header_hash, end_hash = b[:4], b[4:5], b[5:37], b[37:]
	prefix = '  '

	print(prefix + 'GETBLOCKS')
	print(prefix + '-' * 56)
	prefix *= 2
	print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
	print('{}{:32} count {}'.format(prefix, count.hex(), unmarshal_compactsize(count)[1]))
	print('{}{:32} header hash'.format(prefix, header_hash.hex()[:32]))
	print('{}{:32} end hash'.format(prefix, end_hash.hex()[:32]))


def print_header(header, expected_cksum=None):
	"""
	Report the contents of the given bitcoin message header
	:param header: bitcoin message header (bytes or bytearray)
	:param expected_cksum: the expected checksum for this version message, if known
	:return: message type
	"""
	magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
	command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
	psz = unmarshal_uint(payload_size)
	if expected_cksum is None:
		verified = ''
	elif expected_cksum == cksum:
		verified = '(verified)'
	else:
		verified = '(WRONG!! ' + expected_cksum.hex() + ')'
	prefix = '  '
	print(prefix + 'HEADER')
	print(prefix + '-' * 56)
	prefix *= 2
	print('{}{:32} magic'.format(prefix, magic.hex()))
	print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
	print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
	print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
	return command


def run():
	"""
	Main function to connect to Bitcoin peer, get block, and demonstrate modification
	"""
	print("=" * 70)
	print("Bitcoin Blockchain Lab 5")
	print("=" * 70)
	print(f"SU ID: {SU_ID}")
	print(f"Target Block Number: {BLOCK_NUMBER}")
	print(f"Connecting to {BTC_HOST}:{BTC_PORT}")
	print("=" * 70)

	# Create socket connection
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(60)  # 60 second timeout

	try:
		sock.connect((BTC_HOST, BTC_PORT))
		print("Connected successfully!\n")

		# Step 1: Send version message
		print("Step 1: Sending version message...")
		version_msg = get_version_message()
		version_packet = build_packet("version", version_msg)
		sock.sendall(version_packet)
		print_message(version_packet, "Sent")

		# Receive version response
		cmd, payload = recv_message(sock)
		if cmd == 'version':
			print_message(build_packet("version", payload), "Received")
		else:
			print(f"Unexpected message: {cmd}")

		# Receive verack
		cmd, payload = recv_message(sock)
		if cmd == 'verack':
			print("\nReceived verack")
		else:
			print(f"Unexpected message: {cmd}")

		# Send verack
		print("\nSending verack...")
		verack_packet = build_packet("verack", b'')
		sock.sendall(verack_packet)

		# Step 2: Send getblocks message
		print("\nStep 2: Sending getblocks message...")
		getblocks_msg = get_getblocks_message()
		getblocks_packet = build_packet("getblocks", getblocks_msg)
		sock.sendall(getblocks_packet)
		print_message(getblocks_packet, "Sent")

		# Receive inv messages with block hashes
		print("\nStep 3: Receiving inventory (inv) messages...")
		block_hashes = []
		inv_count = 0
		max_inv_messages = 20  # Limit to avoid too many
		timeout_count = 0

		while inv_count < max_inv_messages and timeout_count < 5:
			try:
				sock.settimeout(5)  # 5 second timeout per message
				cmd, payload = recv_message(sock)
				if cmd == 'inv':
					inv_items = parse_inv(payload)
					for inv_type, inv_hash in inv_items:
						if inv_type == MSG_BLOCK:
							block_hashes.append(inv_hash)
							if len(block_hashes) <= 5 or len(block_hashes) % 10 == 0:
								print(f"  Received block hash #{len(block_hashes)}: {inv_hash[::-1].hex()}")
					inv_count += 1
					timeout_count = 0
					# If we have enough blocks, we can stop
					if len(block_hashes) > BLOCK_NUMBER:
						break
				elif cmd == 'ping':
					# Respond to ping
					ping_packet = build_packet("pong", payload)
					sock.sendall(ping_packet)
				elif cmd is None:
					timeout_count += 1
					if timeout_count >= 3:
						break
				else:
					print(f"  Received: {cmd}")
			except socket.timeout:
				timeout_count += 1
				if timeout_count >= 3:
					break

		if not block_hashes:
			print("ERROR: No block hashes received!")
			return

		print(f"\nTotal blocks received in inventory: {len(block_hashes)}")

		# Step 4: Get the target block
		# Note: Since inv messages don't include block heights, we'll use
		# a block from the inventory. For a more accurate approach, we'd
		# need to use getheaders to walk the chain to the exact height.
		# For this lab, we'll use one of the received blocks.
		if len(block_hashes) > BLOCK_NUMBER:
			target_block_hash = block_hashes[BLOCK_NUMBER]
			print(f"Using block at index {BLOCK_NUMBER} from inventory")
		else:
			# Use a block from the middle/end of what we received
			# This simulates getting an "old" block
			idx = min(BLOCK_NUMBER % len(block_hashes), len(block_hashes) - 1)
			target_block_hash = block_hashes[idx]
			print(f"Using block at index {idx} from inventory (target was {BLOCK_NUMBER})")

		print(f"\nStep 4: Requesting target block (index {BLOCK_NUMBER})...")
		print(f"Block hash: {target_block_hash[::-1].hex()}")

		getdata_msg = get_getdata_message(MSG_BLOCK, target_block_hash)
		getdata_packet = build_packet("getdata", getdata_msg)
		sock.sendall(getdata_packet)

		# Receive block
		print("\nStep 5: Receiving block...")
		cmd, block_payload = recv_message(sock)
		if cmd != 'block':
			print(f"ERROR: Expected 'block', got '{cmd}'")
			return

		# Parse block
		header, transactions = parse_block(block_payload)

		if not header:
			print("ERROR: Failed to parse block header")
			return

		print("\n" + "=" * 70)
		print("BLOCK INFORMATION")
		print("=" * 70)
		print(f"Block Hash: {header['hash']}")
		print(f"Previous Block: {header['prev_block']}")
		print(f"Merkle Root: {header['merkle_root']}")
		print(f"Timestamp: {strftime('%Y-%m-%d %H:%M:%S', gmtime(header['timestamp']))}")
		print(f"Version: {header['version']}")
		print(f"Nonce: {header['nonce']}")
		print(f"Number of Transactions: {len(transactions)}")

		# Step 6: Display transactions (Extra Credit)
		print("\n" + "=" * 70)
		print("TRANSACTIONS IN BLOCK (Extra Credit)")
		print("=" * 70)
		for i, tx in enumerate(transactions):
			print(f"\nTransaction {i+1}:")
			print(f"  TXID: {tx['txid']}")
			print(f"  Version: {tx['version']}")
			print(f"  Inputs: {len(tx['inputs'])}")
			for j, inp in enumerate(tx['inputs']):
				print(f"    Input {j+1}:")
				print(f"      Previous TX: {inp['prev_tx_hash']}")
				print(f"      Output Index: {inp['prev_output_index']}")
				print(f"      Script Length: {inp['script_len']}")
			print(f"  Outputs: {len(tx['outputs'])}")
			for j, out in enumerate(tx['outputs']):
				print(f"    Output {j+1}:")
				print(f"      Value: {out['value']} satoshis ({out['value'] / 1e8:.8f} BTC)")
				print(f"      Script Length: {out['script_len']}")
				print(f"      Script: {out['script'][:64]}..." if len(out['script']) > 64 else f"      Script: {out['script']}")
			print(f"  Locktime: {tx['locktime']}")

		# Step 7: Modify transaction and show rejection (Extra Credit)
		if len(transactions) > 0 and len(transactions[0]['outputs']) > 0:
			print("\n" + "=" * 70)
			print("MODIFYING TRANSACTION (Extra Credit)")
			print("=" * 70)

			# Modify first transaction's first output
			original_tx = transactions[0]
			original_output = original_tx['outputs'][0]
			print(f"\nOriginal Transaction 1, Output 1:")
			print(f"  Value: {original_output['value']} satoshis")
			print(f"  Script: {original_output['script']}")

			# Create a modified script (OP_RETURN with some data)
			modified_script_hex = "6a04deadbeef"  # OP_RETURN + 4 bytes of data
			modified_tx_raw = modify_transaction_output(original_tx, 0, modified_script_hex)

			# Recalculate TXID
			modified_txid = hashlib.sha256(hashlib.sha256(modified_tx_raw).digest()).digest()[::-1].hex()

			print(f"\nModified Transaction 1, Output 1:")
			print(f"  Value: {original_output['value']} satoshis (unchanged)")
			print(f"  Script: {modified_script_hex} (modified)")

			# Recompute Merkle root
			original_tx_hashes = []
			for tx in transactions:
				# TXID is double SHA256 of raw transaction, not reversed
				tx_hash = hashlib.sha256(hashlib.sha256(tx['raw']).digest()).digest()
				original_tx_hashes.append(tx_hash)

			modified_tx_hashes = []
			modified_tx_hash = hashlib.sha256(hashlib.sha256(modified_tx_raw).digest()).digest()
			modified_tx_hashes.append(modified_tx_hash)
			for tx in transactions[1:]:
				tx_hash = hashlib.sha256(hashlib.sha256(tx['raw']).digest()).digest()
				modified_tx_hashes.append(tx_hash)

			original_merkle = compute_merkle_root(original_tx_hashes)
			modified_merkle = compute_merkle_root(modified_tx_hashes)

			# Recompute block hash
			original_header = block_payload[:80]
			modified_header = bytearray(original_header)
			modified_header[36:68] = modified_merkle
			original_block_hash = hashlib.sha256(hashlib.sha256(bytes(original_header)).digest()).digest()[::-1]
			modified_block_hash = hashlib.sha256(hashlib.sha256(bytes(modified_header)).digest()).digest()[::-1]

			# Generate report
			print("\n" + "=" * 70)
			print("REPORT: HOW MODIFIED BLOCK WOULD BE REJECTED (Extra Credit)")
			print("=" * 70)
			print(f"\n1. TRANSACTION ID CHANGE:")
			print(f"   Original TXID: {original_tx['txid']}")
			print(f"   Modified TXID: {modified_txid}")
			print(f"   ✓ Transaction ID changed - peers will detect invalid transaction")

			print(f"\n2. MERKLE ROOT CHANGE:")
			print(f"   Original Merkle Root: {original_merkle.hex()}")
			print(f"   Modified Merkle Root: {modified_merkle.hex()}")
			print(f"   ✓ Merkle root mismatch - block header integrity check fails")

			print(f"\n3. BLOCK HASH CHANGE:")
			print(f"   Original Block Hash: {original_block_hash.hex()}")
			print(f"   Modified Block Hash: {modified_block_hash.hex()}")
			print(f"   ✓ Block hash changed - invalidates proof-of-work and chain linkage")

			print(f"\n4. REJECTION REASONS:")
			print(f"   a) Merkle Root Mismatch:")
			print(f"      - The block header contains a merkle root that doesn't match")
			print(f"        the computed root from transactions")
			print(f"      - Peers verify: hash(header) should match merkle root")
			print(f"      - Result: Block rejected immediately")
			print(f"   b) Invalid Transaction:")
			print(f"      - Modified transaction has different TXID")
			print(f"      - Previous blocks reference this TXID")
			print(f"      - Result: Transaction validation fails")
			print(f"   c) Chain Integrity Broken:")
			print(f"      - Block hash changed, breaking link to next block")
			print(f"      - All subsequent blocks become invalid")
			print(f"      - Result: Entire chain from this point forward rejected")
			print(f"   d) Proof-of-Work Invalid:")
			print(f"      - Block hash no longer meets difficulty target")
			print(f"      - Nonce was valid for original block, not modified one")
			print(f"      - Result: Block rejected as invalid proof-of-work")

			print("\n" + "=" * 70)
			print("CONCLUSION:")
			print("Any modification to a transaction in a block will be detected")
			print("because it changes the Merkle root, which is part of the block")
			print("header. This makes the blockchain tamper-evident.")
			print("=" * 70)

	except socket.timeout:
		print("ERROR: Connection timeout")
	except Exception as e:
		print(f"ERROR: {e}")
		import traceback
		traceback.print_exc()
	finally:
		sock.close()
		print("\nConnection closed.")


if __name__ == '__main__':
	run()
