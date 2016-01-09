CBC FUNCTIONS v1.0 README
=========================

INSTALL
=======
Copy the /lib dir to your /eggdrop/lib dir
Copy the cbc_functions.tcl file to your /eggdrop/scripts dir
Load the script in eggdrop.conf
    ex.: source scripts/cbc_functions.tcl

GENERAL USAGE
=============
- cbc_encrypt <key> <text>
   will encrypt your plain <text> in CBC mode with <key>

- cbc_decrypt <key> <text>
   will decrypt your CBC encrypted <text> with <key>


USE WITH TCLEGGDROP_MCPSFUNCS (MCEGGDROP)
=========================================
mceggdrop will automatically use these functions if you have this script
 installed; it will be used to encrypt and decrypt any encryption where
 the key starts with a cbc: or cbc; prefix
 (i.e. use cbc:test to use cbc mode encryption with key of 'test')


GREETINGS
=========
I would like to thanks: 

- Mouser for mircryption 1.11

- Sourceforge tcllib team for their great modules
  Blowfish Module v1.3
    http://cvs.sourceforge.net/viewcvs.py/tcllib/tcllib/modules/blowfish/
  Base64 Module v2.3.1
    http://cvs.sourceforge.net/viewcvs.py/tcllib/tcllib/modules/base64/

- Frank Pilhofer for the Mersenne Twister PRNG
  mt_rand Module v1.0.0
    http://wiki.tcl.tk/13121


Have fun
B0unTy
