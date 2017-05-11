#! usr/bin/env

# My RSA functions

# Time taken
# 100 of BLOCK SIZE 16 = 88.6s
# 100 of BLOCK SIZE 32 = 84.4s
# 100 of BLOCK SIZE 128 = 78.4s

import math, random
import rabin_miller, utility

DEFAULT_BLOCK_SIZE = 32
BYTE_SIZE = 256

def generate_values(keysize=1024):
	p = rabin_miller.generate_large_prime(keysize)
	q = rabin_miller.generate_large_prime(keysize)
	n = p * q
	totient = n - p - q + 1 # Tot(n)
	while True:
		e = random.randrange(2 ** (keysize - 1), 2 ** keysize) #Find a coprime
		if utility.gcd(e, totient) == 1: # verify e is coprime
			break
	d = utility.modular_multiplicative_inverse(e, totient)
	#print(totient, e, d)
	return n, e, d

def encrypt(message, n, e):
	encrypt_blocks = encrypt_message(message, n, e)
	# Convert large int values to one string value
	encrypt_blocks = [str(block) for block in encrypt_blocks]
	encrypted_content = ','.join(encrypt_blocks)
	return encrypted_content

# Converts message string into a list of block integers.
# Then encrypts each block integer.
# Returns encrypted hash
def encrypt_message(message, n, e):
	encrypt_blocks = []
	for block in get_blocks_from_text(message):
		# cipher = plain ^ e mod n
		encrypt_blocks.append(pow(block, e, n))
	return encrypt_blocks

def get_blocks_from_text(message, block_size=DEFAULT_BLOCK_SIZE):
	# Converts a string message to a list of block integers.
	# Each integer represents block_size string characters

	message_bytes = message.encode('ascii')
	import binascii

	block_ints = []
	for block_start in range(0, len(message_bytes), block_size):
		# Calculate the block integer for this block of text
		block_int = 0
		for i in range(block_start, min(block_start + block_size, len(message_bytes))):
			block_int += int(binascii.hexlify(message_bytes[i]), 16) * (BYTE_SIZE ** (i % block_size))
		block_ints.append(block_int)
	return block_ints

def decrypt(encrypted_message, n, d):
	encrypted_blocks = []
	for block in encrypted_message.split(','):
		encrypted_blocks.append(int(block))
	return decrypt_message(encrypted_blocks, n, d)

def decrypt_message(encrypt_blocks, n, d):
	decrypt_blocks = []
	for block in encrypt_blocks:
		# plain = cipher ^ d mod n
		decrypt_blocks.append(pow(block, d, n))
	return get_text_from_blocks(decrypt_blocks)

def get_text_from_blocks(block_ints, block_size=DEFAULT_BLOCK_SIZE):
	# Converts a list of block integers to the original message string.
	message = []
	for block_int in block_ints:
		block_message = []
		for i in range(block_size - 1, -1, -1): # reversed
			idx = BYTE_SIZE ** i
			ascii_num = block_int / idx
			block_int = block_int % idx
			block_message.insert(0, chr(ascii_num))
		message.extend(block_message)
	return ''.join(message)

def main():
	n, e, d = generate_values(1024)
	message = 'Hello World.'
	print('message', message)
	encrypted_message = encrypt(message, n, e)
	print('encrypted_message', encrypted_message)
	decrypted_message = decrypt(encrypted_message, n, d)
	print('decrypted_message', decrypted_message)

if __name__ == '__main__':
	main()