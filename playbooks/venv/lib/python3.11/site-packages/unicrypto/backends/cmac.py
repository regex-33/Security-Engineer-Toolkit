# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (beto@coresecurity.com)
#
# Description:
#   RFC 4493 implementation (https://www.ietf.org/rfc/rfc4493.txt)
#   RFC 4615 implementation (https://www.ietf.org/rfc/rfc4615.txt)
#
#   NIST SP 800-108 Section 5.1, with PRF HMAC-SHA256 implementation
#   (https://tools.ietf.org/html/draft-irtf-cfrg-kdf-uses-00#ref-SP800-108)
#
#   [MS-LSAD] Section 5.1.2
#   [MS-SAMR] Section 2.2.11.1.1

from struct import pack, unpack

def CMAC(K, M, length, cipherobj):

#   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#   +                   Algorithm AES-CMAC                              +
#   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#   +                                                                   +
#   +   Input    : K    ( 128-bit key )                                 +
#   +            : M    ( message to be authenticated )                 +
#   +            : len  ( length of the message in octets )             +
#   +   Output   : T    ( message authentication code )                 +
#   +                                                                   +
#   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#   +   Constants: const_Zero is 0x00000000000000000000000000000000     +
#   +              const_Bsize is 16                                    +
#   +                                                                   +
#   +   Variables: K1, K2 for 128-bit subkeys                           +
#   +              M_i is the i-th block (i=1..ceil(len/const_Bsize))   +
#   +              M_last is the last block xor-ed with K1 or K2        +
#   +              n      for number of blocks to be processed          +
#   +              r      for number of octets of last block            +
#   +              flag   for denoting if last block is complete or not +
#   +                                                                   +
#   +   Step 1.  (K1,K2) := Generate_Subkey(K);                         +
#   +   Step 2.  n := ceil(len/const_Bsize);                            +
#   +   Step 3.  if n = 0                                               +
#   +            then                                                   +
#   +                 n := 1;                                           +
#   +                 flag := false;                                    +
#   +            else                                                   +
#   +                 if len mod const_Bsize is 0                       +
#   +                 then flag := true;                                +
#   +                 else flag := false;                               +
#   +                                                                   +
#   +   Step 4.  if flag is true                                        +
#   +            then M_last := M_n XOR K1;                             +
#   +            else M_last := padding(M_n) XOR K2;                    +
#   +   Step 5.  X := const_Zero;                                       +
#   +   Step 6.  for i := 1 to n-1 do                                   +
#   +                begin                                              +
#   +                  Y := X XOR M_i;                                  +
#   +                  X := AES-128(K,Y);                               +
#   +                end                                                +
#   +            Y := M_last XOR X;                                     +
#   +            T := AES-128(K,Y);                                     +
#   +   Step 7.  return T;                                              +
#   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

	const_Bsize = 16
	const_Zero  = bytearray(16)

	AES_128= cipherobj(K)
	M      = bytearray(M[:length])
	K1, K2 = Generate_Subkey(K, cipherobj)
	n      = len(M)//const_Bsize

	if n == 0:
		n = 1
		flag = False
	else:
		if (length % const_Bsize) == 0:
			flag = True
		else:
			n += 1
			flag = False

	M_n = M[(n-1)*const_Bsize:]
	if flag is True:
		M_last = XOR_128(M_n,K1)
	else:
		M_last = XOR_128(PAD(M_n),K2)

	X = const_Zero
	for i in range(n-1):
		M_i = M[(i)*const_Bsize:][:16]
		Y   = XOR_128(X, M_i)
		X   = bytearray(AES_128.encrypt(bytes(Y)))
	Y = XOR_128(M_last, X)
	T = AES_128.encrypt(bytes(Y))

	return T


def Generate_Subkey(K, cipherobj):

#   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#   +                    Algorithm Generate_Subkey                      +
#   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#   +                                                                   +
#   +   Input    : K (128-bit key)                                      +
#   +   Output   : K1 (128-bit first subkey)                            +
#   +              K2 (128-bit second subkey)                           +
#   +-------------------------------------------------------------------+
#   +                                                                   +
#   +   Constants: const_Zero is 0x00000000000000000000000000000000     +
#   +              const_Rb   is 0x00000000000000000000000000000087     +
#   +   Variables: L          for output of AES-128 applied to 0^128    +
#   +                                                                   +
#   +   Step 1.  L := AES-128(K, const_Zero);                           +
#   +   Step 2.  if MSB(L) is equal to 0                                +
#   +            then    K1 := L << 1;                                  +
#   +            else    K1 := (L << 1) XOR const_Rb;                   +
#   +   Step 3.  if MSB(K1) is equal to 0                               +
#   +            then    K2 := K1 << 1;                                 +
#   +            else    K2 := (K1 << 1) XOR const_Rb;                  +
#   +   Step 4.  return K1, K2;                                         +
#   +                                                                   +
#   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

	AES_128 = cipherobj(K)

	L = AES_128.encrypt(bytes(bytearray(16)))

	LHigh = unpack('>Q',L[:8])[0]
	LLow  = unpack('>Q',L[8:])[0]

	K1High = ((LHigh << 1) | ( LLow >> 63 )) & 0xFFFFFFFFFFFFFFFF
	K1Low  = (LLow << 1) & 0xFFFFFFFFFFFFFFFF

	if (LHigh >> 63):
		K1Low ^= 0x87

	K2High = ((K1High << 1) | (K1Low >> 63)) & 0xFFFFFFFFFFFFFFFF
	K2Low  = ((K1Low << 1)) & 0xFFFFFFFFFFFFFFFF

	if (K1High >> 63):
		K2Low ^= 0x87

	K1 = bytearray(pack('>QQ', K1High, K1Low))
	K2 = bytearray(pack('>QQ', K2High, K2Low))

	return K1, K2

def XOR_128(N1,N2):

	J = bytearray()
	for i in range(len(N1)):
		#J.append(indexbytes(N1,i) ^ indexbytes(N2,i))
		J.append(N1[i] ^ N2[i])
	return J

def PAD(N):
	padLen = 16-len(N)
	return  N + b'\x80' + b'\x00'*(padLen-1)