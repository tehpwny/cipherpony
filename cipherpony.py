#!/bin/python

# adapted from Eli Bendersky
# http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/

import os, random, struct, sys
import hashlib
import base64
import getpass
from Crypto.Cipher import AES
from Crypto import Random


def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    #iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    iv = Random.get_random_bytes(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    try:
        filesize = os.path.getsize(in_filename)
    except FileNotFoundError:
        print('File {0} not found'.format(in_filename))
        sys.exit()
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))

def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)



if len(sys.argv) == 1:
    print('''
          Usage : \r\n
          \tcipherpony.py -e file [-o outfilename]\t encrypt a file\r\n
          \t\tDefault filename will be input_file.enc
          \tcipherpony.py -d file [-o outfilename]\t decrypt a file \r\n
          \t\tDefault filename will be input_file without its last extension (ex nsa.txt.enc will be nsa.txt)''')
    sys.exit()

if sys.argv[1] == '-e':
    try:
        outfile = sys.argv[sys.argv.index('-o') + 1]
    except ValueError:
        outfile = None
        pass
    key = getpass.getpass()
    encrypt_file(hashlib.sha256(base64.b64encode(key.encode())).digest(),sys.argv[2],outfile)
    rm = input('Remove original file ? (y/N)')
    if rm.lower() == 'y':
        os.remove(os.path.realpath(sys.argv[2]))

elif sys.argv[1] == '-d':
    try:
        outfile = sys.argv[sys.argv.index('-o') + 1]
    except ValueError:
        outfile = None
        pass

    key = getpass.getpass()
    try:
        decrypt_file(hashlib.sha256(base64.b64encode(key.encode())).digest(),sys.argv[2],outfile)
    except struct.error as e:
        print('Wrong input file')
