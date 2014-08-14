cipherpony
==========

Python tool to encrypt/decrypt files with AES

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
