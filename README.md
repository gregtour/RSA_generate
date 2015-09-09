# RSA Key Generator

  First, run the application and save the output to a file: ..key.asn1. This file contains your new public and private key, based on the settings configured in rsa_gen.cpp. To use this key with SSH follow the steps below, otherwise it is possible to encrypt and decrypt data just with this information.
  
  
  Run: `openssl asn1parse -genconf ..key.asn1 -out key.der`
  
  
  Followed by: `openssl rsa -in key.der -inform der -text -check -out id_rsa`
  
  
  Then: `ssh-keygen -y -f id_rsa > id_rsa.pub`.
  
  
  To generate private and public key files.
  
# Explanation

The key generator iterates through very large numbers (308 digit numbers for 2048-bit security) until it finds one that is almost certainly prime. This is repeated once and then these values are used to build an RSA key. 

Numbers are generated randomly using:
  a) The system time.
  b) The CPU's tick count.
  c) The built-in rand() function from the standard library.
  d) A 1024-bit and 128-bit XOR shift random number generator.
  
It would be possible to use additional sources of random information to increase the entropy of a key. 

Random numbers are generated digit-by-digit in base 10 then converted to a *BigInteger*. Potential composite numbers are test divided by the first 10,840 prime numbers, then compared with two probabilistic prime tests for one thousand random tests before they are determined to be prime.

The key generator the finds an 8-bit or slightly larger public exponent (e) and computes all of the other fields for an SSH private key.
 
# Attribution

BigInteger C++ implementation written and maintained by Matt McCutchen (http://mattmccutchen.net/bigint/). 

XorShift Random credits go to Sebastiano Vigna.
