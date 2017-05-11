#! usr/bin/env python2.7

# Patrick Bradley

"""
 # A simple PGPlike encryption algorithm
 # To start, you want to pass data from A to B.
 # Encrypt
 # Step 1: Receive or have access to B's public key.
 # Step 2: Generate a random key for each message.
 # Step 3: Encrypt data using random key.
 # Step 4: Encrypt key using B's public key (use RSA).
 # Step 5: Send both to B.
 # Decrypt
 # Step 1: Decode key using own (B's) private key.
 # Step 2: Decode data using decoded key

 # RSA
 # Step 1: Choose two distinct prime numbers p and q, chosen at random and near in length.
 # Step 2: Compute n = pq
 # Step 3: len(n) = key length
 # Step 4: Compute the totient of n, OR (p-1)(q-1) OR n - (p + q - 1). Do not share this value
 # Step 5: Choose an integer e that is less than the totient of n and the greatest common denominator of e and tot(n) is 1.
 #         This ensures e and tot(n) are coprime.
 # Step 6: d = e_inverse mod(tot(n)) OR de = 1 mod(tot(n))
 # Step 7: Your public key is (n, e)
 # Step 8: Your private key is (n, d)

 # To Encrypt plaintext message:
 # c(m) = m^e mod n
 # To Decrypt encrypted message:
 # m(c) = c^d mod n

"""

import os, sys
import pickle
from collections import OrderedDict
import rsa.RSA as RSA

class App(object):
    def __init__(self):
        self.version = 'Version: Bradley PGPlike. DO NOT USE THIS FOR REAL CRYPTOGRAPHY!'
        self.n, self.e, self.d = None, None, None
        self.keys = OrderedDict()

        self.load_info()

    def load_info(self):
        if os.path.exists('keyring.p'):
            with open('keyring.p', 'rb') as loadFile:
                self.keys = pickle.load(loadFile)

        if 'self_public' in self.keys:
            with open(self.keys['self_public'], 'r') as pub:
                lines = pub.readlines()
                self.n = int(lines[3])
                self.e = int(lines[4])

        if 'self_private' in self.keys:
            with open(self.keys['self_private'], 'r') as priv:
                lines = priv.readlines()
                self.n = int(lines[3])
                self.d = int(lines[4])

    def save_keys(self):
        with open('keyring.p', 'wb', pickle.HIGHEST_PROTOCOL) as key_file:
            pickle.dump(self.keys, key_file)

    def display_help(self):
        print("Valid Commands:")
        print("help - Displays commands.")
        print("encrypt [file] {recipient} - Encrypts file using recipients public key.")
        print("decrypt [file]* - Decrypts file using own private key.")
        print("gen_key - Generates a new public and private key for you to use.")
        print("import [id] [file] - Imports a public key (file) under the name id.")
        print("list_keys - Lists all keys currently loaded.")

    def parse_res(self, split_line):
        #split_line = res.split(' ')
        if split_line[0] == 'help':
            self.display_help()

        # Encrypts a message or a text document with your private key
        elif split_line[0] == 'encrypt':
            if len(split_line) == 1:
                print("Error: Required format is 'encrypt [filename] {recipient ids}'")
                return
            file_name = split_line[1]
            recipients = []
            if len(split_line) > 2:
                recipients = split_line[2:]
            else:
                print("Enter recipient:")
                recipients.append(raw_input("> "))
            self.encrypt_file(file_name, recipients)

        # Decrypts a text document with a given public key
        elif split_line[0] == 'decrypt':
            if self.n and self.d:
                if len(split_line) >= 2:
                    fp_names = split_line[1:]
                    self.decrypt_file(fp_names)
                else:
                    print("Error: Need name of file to decrypt")
            else:
                print("Error: No keys for self on file.")
                print("Use gen_key to generate new PGPlike keys")

        # Generates your public and private key
        elif split_line[0] == 'gen_key':
            if self.n:
                while(True):
                    print("Warning: Your keys already exist. Proceed anyway? (y/n)")
                    ans = raw_input("> ")
                    if ans == 'y':
                        break
                    elif ans == 'n':
                        return

            self.n, self.e, self.d = RSA.generate_values(1024)
            with open('self_public_key.asc', 'w') as fp:
                fp.write('-----BEGIN PGP PUBLIC KEY BLOCK-----\n')
                fp.write(self.version + '\n')
                fp.write('\n')
                fp.write(str(self.n) + '\n')
                fp.write(str(self.e) + '\n')
                fp.write('-----END PGP PUBLIC KEY BLOCK-----')
                print("Wrote public key to self_public_key.asc...")
            with open('self_private_key.asc', 'w') as fp:
                fp.write('-----BEGIN PGP PRIVATE KEY BLOCK-----\n')
                fp.write(self.version + '\n')
                fp.write('\n')
                fp.write(str(self.n) + '\n')
                fp.write(str(self.d) + '\n')
                fp.write('-----END PGP PRIVATE KEY BLOCK-----')
                print("Wrote private key to self_private_key.asc...")
            self.keys['self_public'] = os.path.abspath('self_public_key.asc')
            self.keys['self_private'] = os.path.abspath('self_private_key.asc')

        elif split_line[0] == 'import':
            if len(split_line) != 3:
                print("Error: Format is 'import {id} {public_key_file}")
                return
            name = split_line[1]
            filename = split_line[2]
            if os.path.exists(filename):
                if self.check_valid(filename):
                    self.keys[name] = os.path.abspath(filename)
                    print(filename + ' successfully imported as ' + name + "'s public key.")
                else:
                    print("Error: " + filename + " is not valid public key")
            else:
                print("Error: Cannot locate " + filename)

        elif split_line[0] == 'list_keys':
            for idx, (name, loc) in enumerate(self.keys.iteritems()):
                print(str(idx) + " " + name + " " + loc)

    def encrypt_file(self, filename, recipients):
        message = None
        # Check if file exists
        if os.path.exists(filename):
            with open(filename, 'r') as fp:
                message = fp.read()
        else:
            print("Error: Cannot find file " + filename)
            return

        # Send it to each recipient
        for recipient in recipients:
            if recipient in self.keys:
                fp = self.keys[recipient]
                n, e = None, None
                with open(fp, 'r') as pub_key:
                    lines = pub_key.readlines()
                    n = int(lines[3])
                    e = int(lines[4])
                encrypted_message = RSA.encrypt(message, n, e)
                with open(filename + '.pgp', 'w') as fp:
                    fp.write('-----BEGIN PGP MESSAGE-----\n')
                    fp.write('Version: Bradley PGPlike - message encoded with ' + recipient + ' public key\n')
                    fp.write('\n')
                    fp.write(encrypted_message+'\n')
                    fp.write('-----END PGP MESSAGE-----')
                print("Message encoded to " + recipient)
            else:
                print("Error: Recipient " + recipient + " not found in keys!")

    def decrypt_file(self, filenames):
        for fp in filenames:
            if os.path.exists(fp):
                file_lines = []
                with open(fp, 'r') as to_decrypt:
                    file_lines = to_decrypt.readlines()
                encrypted_message = file_lines[3]
                decrypted_message = RSA.decrypt(encrypted_message, self.n, self.d)
                new_fp = 'decrypt_' + fp
                with open(new_fp, 'w') as out:
                    out.write(decrypted_message)
                print("Saved decrypted_message to " + new_fp)
            else:
                print("Error: Could not decrypt " + fp + ". File does not exist!")

    def check_valid(self, filename):
        with open(filename, 'r') as fp:
            lines = [line.strip() for line in fp.readlines()]
            if lines[0] != '-----BEGIN PGP PUBLIC KEY BLOCK-----':
                print('Line 0 is not "-----BEGIN PGP PUBLIC KEY BLOCK-----"')
                return False
            if lines[1] != self.version:
                print("Error: This code only works with its own PGPlike keys! Remember, do not use this for REAL cryptography!")
                return False
            if lines[5] != '-----END PGP PUBLIC KEY BLOCK-----':
                print('Line 5 is not "-----END PGP PUBLIC KEY BLOCK-----"')
                return False
        return True

if __name__ == '__main__':
    my_app = App()
    if len(sys.argv) < 2:
        my_app.display_help()
    else:
        my_app.parse_res(sys.argv[1:])
        my_app.save_keys()