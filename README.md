cipherpony
==========

Python tool to encrypt/decrypt files with AES

The intended duty of this software is to provide a
simple way to encrypt a file without a 'down side'
of GPG (what you should use for that):
* Absolutely user hostile (until they cryptoparty!)

It is not intended to replace GPG, it is a quick
anonymous file encryption tool, like for your
daily princess diary or your cat pictures folder.

It is still in developpement so changes will happen
like the cipher mode and the hashing method to
become more secure.

DISCL4M3R
=========
```
#################################################

 THIS SOFTWARE IS MAGICAL VOODOO CRYPTOGRAPHY

 YOU SHOULD NOTE THAT IT IS ONLY EXPERIMENTAL
 AND YOU SHOULD NOT USE IT EXCEPT FOR VOODOO
 RECIPES MAYBE.

 DO NOT USE IT ON SERIOUS INFORMATIONS, IF
 YOU ARE A REAL TERRORIST THEN YOU SHOULD
 LEARN TO USE PGP WHICH IS MORE SERIOUS
 CRYPTO-VOODOO

 Ah, also, AND OF COURSE I'M NOT RESPONSIBLE FOR
 ANY DATA LOSS, PROSECUSION, JAIL TIME, DEATH
 SENTENCES, EXPLOSIONS OR ANYTHING CIPHERPONY
 WOULD DO.

#################################################
```

Setup
=====
With pip :

```sudo pip install crypto```

*nix:

install the packet python3-crypto with your packet manager


Usage
=====
crypt0l0v3 a file:
```
 cipherpony.py -e file [-o outfilename]  
```
  Default filename will be input_file.enc

decrypt0l0v3 a file:
```
 cipherpony.py -d file [-o outfilename]
 ```
  Default filename will be input_file without its last extension
  (ex nsaleak.txt.enc will be nsaleak.txt)
