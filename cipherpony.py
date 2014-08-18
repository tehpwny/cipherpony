#!/usr/bin/python3.4
# -*- coding: utf-8 -*-
# Author: pwny@lebib.org
# adapted from Eli Bendersky
# http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
#


#################################################
# DISCL4M3R
# THIS SOFTWARE IS MAGICAL VOODOO CRYPTOGRAPHY
#
# YOU SHOULD NOTE THAT IT IS ONLY EXPERIMENTAL
# AND YOU SHOULD NOT USE IT EXCEPT FOR VOODOO
# RECIPES MAYBE.
#
# DO NOT USE IT ON SERIOUS INFORMATIONS, IF
# YOU ARE A REAL TERRORIST THEN YOU SHOULD
# LEARN TO USE PGP WHICH IS MORE SERIOUS
# CRYPTO-VOODOO
#
# Ah, also, AND OF COURSE I'M NOT RESPONSIBLE FOR
# ANY DATA LOSS, PROSECUSION, JAIL TIME, DEATH
# SENTENCES, EXPLOSIONS OR ANYTHING CIPHERPONY
# WOULD DO.
#################################################



import os, random, math, struct, sys, hashlib, base64, getpass
if sys.version_info <= (3, 0):
    sys.stdout.write("Sorry, Python 3.x is required.\n")
    sys.exit()

try:
    from Crypto.Cipher import AES
    from Crypto import Random
except ImportError:
    print('''No crypto module, please install it. ex:\r\n
    \tpip install crypto\r\n
    or install python3-crypto with your packet manager''')
    sys.exit()


def xkcd_entropy_range(entropy):
    ''' Compare entropy (in bits) to xkcd's reference of a good passphrase '''
    xkcd_point = 84.0964047443681 # correcthorsebatterystaple
    return float(entropy) / xkcd_point

def get_entropy(passphrase):
    '''
        Return the entropy (in bits) of passphrase
    '''
    if len(passphrase) == 0:
        return 0

    if passphrase == None:
        return 0
    entropy = float()
    keylen = float(len(passphrase))
    for char in range(256):
        count = float(passphrase.count(chr(char))/keylen)
        if count > 0:
            entropy += - count*math.log(count, 2)
    return entropy*keylen

def entropy_warning(xkcdentropy):
    '''
        Displays a friendly message about security & datalove
    '''
    print('''
      ~*************************************************************************~
                                  Ohai !
                 /\/\\
                /    \   I'm Security Pwny and you see me because your
              ~/(^  ^)   passphrase security is L4M3 !
             ~/  )  (
            ~/   (  )    Here's some reading about passwod entropy:
           ~/     ~~                 http://xkcd.com/936/
          ~/ 1337  |
                                 Here's your score : {0:.2f}%
            (100% being the reference entropy of : 'correcthorsebatterystaple')
                (I stop being annoying if you reach 60% score, promise!)

         The strengh of a chain is equal to it weakest link, if your passphrase
         is too short or based on one or few words someone (let's say the NSA)
         could easely manage a brute-force attack on your secrets.

         AES-256 may feel like one hell of a crypto-thingy but if the pass that
         protect your (or someone's else!) secrets is 'monkey1234' you can just
         get rid of thoses complicated softwares and use pencil and post-it's
         then leave it on your desk, at least no one is really sure if NSA can
         look there (well, I hope).

         Now that you know that,

         DO YOU WISH TO ABORT AND CHOOSE A BETTER PASSPHRASE ?
         (please do it for all the crypto kittens.)

      ~*************************************************************************~
    '''.format(xkcdentropy))
    return input('Cancel and save crypto kittens ? (Y/nope)')

def wrapgetpass():
    '''
        Wraps python's getpass() to handle the lack
        of unicode support by this function
    '''
    try:
        key = getpass.getpass()
        if len(key) == 0:
            print('Empty passphrase, srsly ?')
            sys.exit()
        return key
    except UnicodeDecodeError:
        print('*** Err0r!: Sorry, cipher pony doesn\'t support unicode chars in passphrase :(')
        wrapgetpass()


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
        print('*** Err0r!: File {0} not found'.format(in_filename))
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
    """
        Decrypts a file using AES (CBC mode) with the
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
          Usage :\r\n
          \tcipherpony.py -e file [-o outfilename]\t crypt0l0v3 a file\r\n
          \t\tDefault filename will be input_file.enc\r\n
          \tcipherpony.py -d file [-o outfilename]\t decrypt0l0v3 a file\r\n
          \t\tDefault filename will be input_file without its last extension
          (ex nsaleak.txt.enc will be nsaleak.txt)
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
        print('**********************************************************~')
        print('| Input file : {0}\r\n| Output file : {1}'.format(os.path.realpath(inputfile),out))
        print('**********************************************************~')

        key = wrapgetpass()
        # Guess if the passphrase is good enough
        entropy = get_entropy(key)
        if xkcd_entropy_range(entropy) < 0.6:
            w = entropy_warning(xkcd_entropy_range(entropy)*100)
            print(w.lower())
            if w.lower() == 'nope' or w.lower() == 'n' or w.lower() == 'no':
                print(':(')
            else:
                sys.exit()
        print('Passphrase entropy score: {0}'.format(xkcd_entropy_range(entropy)*100))


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
            print('| Input file : {0}\r\n| Output file : {1}'.format(os.path.realpath(inputfile),out))
            print('**********************************************************~')
        else:
            print('**********************************************************~')
            print('| Input file : {0}\r\n| Output file : {1}'.format(os.path.realpath(inputfile),os.path.realpath(outfile)))
            print('**********************************************************~')
        key = getpass.getpass()

        try:

            decrypt_file(hashlib.sha256(base64.b64encode(key.encode())).digest(),inputfile,outfile)
            print('D3c1ph3r3d : {0} !'.format(os.path.realpath(out)))

        except struct.error as e: # happen when decrypt function can't find a valid IV
            print('*** Err0r!: Wrong input file (unencrypted ?)')

main()
