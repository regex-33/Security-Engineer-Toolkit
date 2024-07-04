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

def KDF_CounterMode(KI, Label, Context, L, hmac_obj):
# Implements NIST SP 800-108 Section 5.1, with PRF HMAC-SHA256
# https://tools.ietf.org/html/draft-irtf-cfrg-kdf-uses-00#ref-SP800-108
# Fixed values:
#  1. h - The length of the output of the PRF in bits, and
#  2. r - The length of the binary representation of the counter i.
# Input: KI, Label, Context, and L.
# Process:
#  1. n := [L/h]
#  2. If n > 2r-1, then indicate an error and stop.
#  3. result(0):= empty .
#  4. For i = 1 to n, do
#    a. K(i) := PRF (KI, [i]2 || Label || 0x00 || Context || [L]2)
#    b. result(i) := result(i-1) || K(i).
#  5. Return: KO := the leftmost L bits of result(n).
	h = 256
	r = 32

	n = L // h

	if n == 0:
		n = 1

	if n > (pow(2,r)-1):
		raise Exception("Error computing KDF_CounterMode")

	result = b''
	K      = b''

	for i in range(1,n+1):
		input = pack('>L', i) + Label + b'\x00' + Context + pack('>L',L)
		K = hmac_obj.new(KI, input, 'sha256').digest()
		result = result + K

	return result[:(L//8)]
