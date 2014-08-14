#!/bin/python

# adapted from Eli Bendersky
# http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/

import os, random, struct, sys, hashlib, base64, getpass
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

def usage():
    print('''
          Usage : \r\n
          \tcipherpony.py -e file [-o outfilename]\t encrypt a file\r\n
          \t\tDefault filename will be input_file.enc\r\n
          \tcipherpony.py -d file [-o outfilename]\t decrypt a file \r\n
          \t\tDefault filename will be input_file without its last extension
          (ex nsa.txt.enc will be nsa.txt)
          ''')

if len(sys.argv) < 3:
    usage()
    sys.exit()

def main():
    '''
        Tool to encrypt/decrypt files with AES

        Usage :
        cipherpony.py -e file [-o outfilename] :     encrypt a file
        Default filename will be input_file.enc

        cipherpony.py -d file [-o outfilename] :     decrypt a file
        Default filename will be input_file without its last extension (ex nsa.txt.enc will be nsa.txt)
    '''

    if os.path.isfile(sys.argv[2]) == False:
        print('*** Err0r!: Wrong input file')
        usage()
        sys.exit()
    try:
        inputfile = sys.argv[2]
    except IndexError:
        usage()
        sys.exit()

    if sys.argv[1] == '-e': # encryption mode
        # handle arguments exeptions
        try:
            outfile = sys.argv[sys.argv.index('-o') + 1]
            out = os.path.realpath(outfile)
        except ValueError: # no -o specified
            outfile = None
            out = os.path.realpath(inputfile) + '.enc'
            print('*** No output file, using default settingz')
            pass
        except IndexError: # -o without filename, kickin' dat damn user!
            usage()
            sys.exit()
        print('***********************************************************')
        print('* Input file : {0}\r\n* Output file : {1}'.format(os.path.realpath(inputfile),out))
        print('***********************************************************')

        key = getpass.getpass()
        encrypt_file(hashlib.sha256(base64.b64encode(key.encode())).digest(),inputfile,outfile)

        rm = input('Remove original file ? (y/N)')
        if rm.lower() == 'y':
            os.remove(os.path.realpath(inputfile))
        print('C1ph3r3d : {0} !'.format(os.path.realpath(out)))

    elif sys.argv[1] == '-d': # decryption mode
        # handle arguments exeptions
        try:
            outfile = sys.argv[sys.argv.index('-o') + 1]
            out = outfile
        except ValueError: # No -o specified
            outfile = None
            out = os.path.realpath(inputfile).split('.')[0]
            print('*** No output file, using default settingz')
            pass
        except IndexError: # -o without filename, kickin' dat damn user!
            usage()
            sys.exit()

        if outfile == None: # disclosure so the user know what will happen
            print('**********************************************************~')
            print('| Input file : {0}\r\n| Output file: {1}'.format(os.path.realpath(inputfile),out))
            print('**********************************************************~')
        else:
            print('**********************************************************~')
            print('| Input file : {0}\r\n| Output file: {1}'.format(os.path.realpath(inputfile),os.path.realpath(outfile)))
            print('**********************************************************~')
        key = getpass.getpass()

        try:
            decrypt_file(hashlib.sha256(base64.b64encode(key.encode())).digest(),inputfile,outfile)
            print('D3c1ph3r3d : {0} !'.format(os.path.realpath(out)))

        except struct.error as e: # happen when decrypt function can't find a valid IV
            print('*** Err0r!: Wrong input file (unencrypted ?)')

main()
