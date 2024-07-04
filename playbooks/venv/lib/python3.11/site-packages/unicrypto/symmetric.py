from abc import ABC, abstractmethod
from unicrypto import get_preferred_cipher
import enum
from unicrypto import logging

class cipherMODE(enum.Enum):
	ECB = enum.auto()
	CBC = enum.auto()
	CTR = enum.auto()
	CCM = enum.auto()
	CFB = enum.auto()
	OFB = enum.auto()
	GCM = enum.auto()

MODE_ECB = cipherMODE.ECB
MODE_CBC = cipherMODE.CBC
MODE_CTR = cipherMODE.CTR
MODE_CCM = cipherMODE.CCM
MODE_CFB = cipherMODE.CFB
MODE_OFB = cipherMODE.OFB
MODE_GCM = cipherMODE.GCM

class symmetricBASE:
	def __init__(self, key:bytes, mode:cipherMODE = cipherMODE.ECB, IV:bytes = None, segment_size:int= 128):
		self.key = key
		self.mode = mode
		self.IV = IV
		self.segment_size = segment_size
		self._cipher = None
		self.setup_cipher()

	@abstractmethod
	def setup_cipher(self):
		#create the _cipher object here
		raise NotImplementedError()

	@abstractmethod
	def encrypt(self, data):
		raise NotImplementedError()

	@abstractmethod
	def decrypt(self):
		raise NotImplementedError()

	@abstractmethod
	def update(self, data):
		raise NotImplementedError()

	@abstractmethod
	def digest(self):
		raise NotImplementedError()

# from impacket
def expand_DES_key(key):
	# Expand the key from a 7-byte password key into a 8-byte DES key
	key  = key[:7]
	key += b'\x00'*(7-len(key))
	s  = (((key[0] >> 1) & 0x7f) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1).to_bytes(1, byteorder = 'big')
	s += ( (key[6] & 0x7f) << 1).to_bytes(1, byteorder = 'big')
	return s
#

def deriveKey(baseKey):
	# 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
	# Let I be the little-endian, unsigned integer.
	# Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
	# Note that because I is in little-endian byte order, I[0] is the least significant byte.
	# Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
	# Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
	key = baseKey.to_bytes(4, byteorder='little', signed=False) #pack('<L',baseKey)
	key1 = [key[0] , key[1] , key[2] , key[3] , key[0] , key[1] , key[2]]
	key2 = [key[3] , key[0] , key[1] , key[2] , key[3] , key[0] , key[1]]
	return expand_DES_key(bytes(key1)),expand_DES_key(bytes(key2))


DES = get_preferred_cipher('DES')
TDES = get_preferred_cipher('TDES')
AES = get_preferred_cipher('AES')
RC4 = get_preferred_cipher('RC4')