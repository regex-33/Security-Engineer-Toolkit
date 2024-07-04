#!/usr/bin/env python

"""
	Copyright (C) 2013 Bo Zhu http://about.bozhu.me

	Permission is hereby granted, free of charge, to any person obtaining a
	copy of this software and associated documentation files (the "Software"),
	to deal in the Software without restriction, including without limitation
	the rights to use, copy, modify, merge, publish, distribute, sublicense,
	and/or sell copies of the Software, and to permit persons to whom the
	Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
	THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
	FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
	DEALINGS IN THE SOFTWARE.

	SkelSec Note: the original code has been modified to work using questionable crypto libraries by myself who is not a cryptographer.
	              I'd say "use it with suspicion" but in truth: just do not use this at all outside of this library.
"""

from unicrypto.backends.pure.external.AES import AESModeOfOperationCTR, AESModeOfOperationECB, Counter

def int_to_bytes(x: int, blocksize = 0) -> bytes:
	if blocksize == 0:
		return x.to_bytes((x.bit_length() + 7) // 8, 'big')
	else:
		return x.to_bytes(blocksize, 'big')

# GF(2^128) defined by 1 + a + a^2 + a^7 + a^128
# Please note the MSB is x0 and LSB is x127
def gf_2_128_mul(x, y):
	assert x < (1 << 128)
	assert y < (1 << 128)
	res = 0
	for i in range(127, -1, -1):
		res ^= x * ((y >> i) & 1)  # branchless
		x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
	assert res < 1 << 128
	return res


class InvalidInputException(Exception):
	def __init__(self, msg):
		self.msg = msg

	def __str__(self):
		return str(self.msg)


class InvalidTagException(Exception):
	def __str__(self):
		return 'The authenticaiton tag is invalid.'


# Galois/Counter Mode with AES-128 and 96-bit IV
class AES_GCM:
	def __init__(self, master_key):
		self.change_key(master_key)

	def change_key(self, master_key):
		#if len(master_key) != 16:
		#	raise InvalidInputException('Master key should be 128-bit')

		self.__master_key = master_key
		self.__aes_ecb = AESModeOfOperationECB(self.__master_key)
		self.__auth_key = self.__aes_ecb.encrypt(b'\x00' * 16)
		self.__auth_key_int = int.from_bytes(self.__auth_key, byteorder='big', signed=False)

		# precompute the table for multiplication in finite field
		table = []  # for 8-bit
		for i in range(16):
			row = []
			for j in range(256):
				row.append(gf_2_128_mul(self.__auth_key_int, j << (8 * i)))
			table.append(tuple(row))
		self.__pre_table = tuple(table)

		self.prev_init_value = None  # reset

	def __times_auth_key(self, val):
		res = 0
		for i in range(16):
			res ^= self.__pre_table[i][val & 0xFF]
			val >>= 8
		return res

	def __ghash(self, aad, txt):
		len_aad = len(aad)
		len_txt = len(txt)

		# padding
		if 0 == len_aad % 16:
			data = aad
		else:
			data = aad + b'\x00' * (16 - len_aad % 16)
		if 0 == len_txt % 16:
			data += txt
		else:
			data += txt + b'\x00' * (16 - len_txt % 16)

		tag = 0
		assert len(data) % 16 == 0
		for i in range(len(data) // 16):
			tag ^= int.from_bytes(data[i * 16: (i + 1) * 16], byteorder='big', signed=False)
			tag = self.__times_auth_key(tag)
		tag ^= ((8 * len_aad) << 64) | (8 * len_txt)
		tag = self.__times_auth_key(tag)

		return tag

	def encrypt(self, init_value, plaintext, auth_data=b''):
		#if len(init_value) != 12:
		#	raise InvalidInputException('IV should be 96-bit')
		# a naive checking for IV reuse
		len_plaintext = len(plaintext)

		if len_plaintext > 0:
			if len(init_value) == 12:
				ctrval_init = init_value + b'\x00\x00\x00\x02' # ends with 2!!!
				ctrval = int.from_bytes(ctrval_init, byteorder='big', signed=False)
				iv_int = int.from_bytes(init_value, byteorder='big', signed=False)
				iv_int = (iv_int << 32) | 1
				iv_int = iv_int.to_bytes(16, byteorder='big', signed=False)	
			else:
				ctrval = self.__ghash(b'', init_value)
				iv_int = ctrval.to_bytes(16, byteorder='big', signed=False)	
				ctrval += 1
			
			counter = Counter(initial_value=ctrval)
			aes_ctr = AESModeOfOperationCTR(self.__master_key, counter=counter)

			if 0 != len_plaintext % 16:
				padded_plaintext = plaintext + \
					b'\x00' * (16 - len_plaintext % 16)
			else:
				padded_plaintext = plaintext
			ciphertext = aes_ctr.encrypt(padded_plaintext)[:len_plaintext]

		else:
			ciphertext = b''
			iv_int = int.from_bytes(init_value, byteorder='big', signed=False)
			iv_int = (iv_int << 32) | 1
			iv_int = iv_int.to_bytes(16, byteorder='big', signed=False)	

		auth_tag = self.__ghash(auth_data, ciphertext)
		iv_int_enc = self.__aes_ecb.encrypt(iv_int)
		iv_int_enc = int.from_bytes(iv_int_enc, byteorder='big', signed=False)

		auth_tag ^= iv_int_enc

		assert auth_tag < (1 << 128)
		return ciphertext, auth_tag.to_bytes(16, byteorder='big', signed=False)

	def decrypt(self, init_value, ciphertext, auth_tag, auth_data=b''):
		if len(auth_tag) != 16:
			raise InvalidInputException('Tag should be 128-bit')

		if len(init_value) == 12:
			iv_int = int.from_bytes(init_value, byteorder='big', signed=False)
			iv_int = (iv_int << 32) | 1
			iv_int = iv_int.to_bytes(16, byteorder='big', signed=False)
			ctrval_init = init_value + b'\x00\x00\x00\x02' # ends with 2!!!
			ctrval = int.from_bytes(ctrval_init, byteorder='big', signed=False)
		else:
			ctrval = self.__ghash(b'', init_value)
			iv_int = int_to_bytes(ctrval, 16)
			ctrval += 1

		iv_int_enc = self.__aes_ecb.encrypt(iv_int)
		iv_int_enc = int.from_bytes(iv_int_enc, byteorder='big', signed=False)
		auth_tag_verify = self.__ghash(auth_data, ciphertext) ^ iv_int_enc
		auth_tag_verify = auth_tag_verify.to_bytes(16, byteorder='big', signed=False)
		if auth_tag != auth_tag_verify:
			raise InvalidTagException

		len_ciphertext = len(ciphertext)
		if len_ciphertext > 0:
			counter = Counter(initial_value=ctrval)
			aes_ctr = AESModeOfOperationCTR(self.__master_key, counter=counter)
			if 0 != len_ciphertext % 16:
				padded_ciphertext = ciphertext + \
					b'\x00' * (16 - len_ciphertext % 16)
			else:
				padded_ciphertext = ciphertext
			plaintext = aes_ctr.decrypt(padded_ciphertext)[:len_ciphertext]

		else:
			plaintext = b''

		return plaintext