cipherpony
==========

Python tool to encrypt/decrypt files with AES

Setup
=====
With pip :

```pip install crypto```

*nix:

install the packet python3-crypto with your packet manager


Usage
=====
encrypt a file:
```
 cipherpony.py -e file [-o outfilename]  
```
  Default filename will be input_file.enc

decrypt a file:
```
 cipherpony.py -d file [-o outfilename]
 ```
  Default filename will be input_file without its last extension (ex nsa.txt.enc will be nsa.txt)
