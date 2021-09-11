# HISE: Hierarchy Integrated Signature and Encryption

## Overview

This project implements (global escrow) HISE. 
HISE sticks to key reuse strategy and features hierarchy key derivation structure simultaneously, 
thus admits secure individual key escrow. 
Global escrow HISE further allows an escrow agent decrypts any ciphertext encrypted under any public key.  

## Specifications

- OS: MAC OS x64

- Language: C++
- Requires: mcl library

- Language: C
- Requires: relic library


## Directory Structure

- README.md

- CMakeLists.txt: cmake file

- /common: print.hpp --- define print function

- /cpk
  * ElGamal.hpp: implement ElGamal PKE
  * Schnorr.hpp: implement Schnorr SIG

- /hise
  * hise1.hpp: implement HISE from Boneh-Franklin IBE
  * hise2.hpp: implement HISE from ElGamal PKE and ZKPoK

- /global_escrow_hise
  * global_escrow_hise1.hpp: implement global escrow HISE from Boneh-Franklin IBE and twisted Naor-Yung paradigm
  * global_escrow_hise2.hpp: implement HISE from a variant of Joux's 3-party NIKE and ZKPoK

- /global_escrow_pke
  * global_escrow_pke1.hpp: implement global escrow PKE from ElGamal PKE and twisted Naor-Yung paradigm
  * global_escrow_pke2.hpp: implement Boneh-Franklin escrow PKE (based on symmetric pairing provided by relic)  
  * global_escrow_pke3.hpp: implement our new global escrow PKE (based on asymmetric pairing)  

- /test: test files
  * test_XXX.cpp

- /build: build files

## Install mcl 
download [mcl](https://github.com/herumi/mcl), then
```
  $ mkdir build && cd build
  $ cmake ..
  $ make
  $ sudo make install
```

## Parameter choices (for 128-bit security level)

- elliptic curve (for hise2, global escrow pke1)
  * The default elliptic curve is "SECP256K1"

- pairing friendly curve (for hise1, global escrow hise 1/2, global escrow pke3)
  * The default curve is "BLS12-381" (ate pairing)

## Install relic 
download [relic](https://github.com/relic-toolkit/relic), then
```
  $ mkdir build
  $ cd build
  $ cmake -DCHECK=off -DARITH=gmp -DBN_PRECI=1536 -DFP_PRIME=1536 -DFP_QNRES=on -DFP_METHD="BASIC;COMBA;COMBA;MONTY;LOWER;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DCOMP="-O2 -funroll-loops -fomit-frame-pointer" ..
  $ make
  $ sudo make install
```

## Parameter choices (for 128-bit security level)
- for global escrow pke2: the default curve is "SS_P1536" (Weil pairing)


## Compile and Run
```
  $ cd build
  $ cmake ..
  $ make
```

## License

This library is licensed under the [MIT License](LICENSE).





