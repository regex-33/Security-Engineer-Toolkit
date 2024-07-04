
from mbedtls import cipher as mbedcipher
from unicrypto.symmetric import symmetricBASE, cipherMODE
import struct
from unicrypto import hashlib

class AES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, segment_size = 128):
		self.ctrint = None
		self.ctrlen = None

		self._ccm_cipher_ctr = None
		self._ccm_cipher_cbc = None
		symmetricBASE.__init__(self, key, mode, IV, segment_size=segment_size)

	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_ECB, b'')
		elif self.mode == cipherMODE.CBC:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CBC, self.IV)
		elif self.mode == cipherMODE.CTR:
			self.ctrlen = len(self.IV)
			self.ctrint = int.from_bytes(self.IV, byteorder = 'big', signed= False)
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CTR, self.IV)
		elif self.mode == cipherMODE.OFB:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_OFB, self.IV)
		elif self.mode == cipherMODE.CFB:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_CFB, self.IV)
		elif self.mode == cipherMODE.CCM:
			if self.segment_size not in (4, 6, 8, 10, 12, 14, 16):
				raise ValueError("Parameter 'mac_len' must be even and in the range 4..16 (not %d)" % self.segment_size)
			if not (self.IV and 7 <= len(self.IV) <= 13):
				raise ValueError("Length of parameter 'nonce' must be in the range 7..13 bytes")

			q = 15 - len(self.IV)
			t_nonce = struct.pack("B", q - 1) + self.IV
			t_noncepad = b'\x00'*(16 - (len(t_nonce) % 16)) # 16 is the blocksize
			t_nonce += t_noncepad
			self.ctrlen = len(t_nonce)
			self.ctrint = int.from_bytes(t_nonce, byteorder = 'big', signed= False)
			self._ccm_cipher_ctr = mbedcipher.AES.new(self.key, mbedcipher.MODE_CTR, t_nonce)
			self._ccm_cipher_cbc = mbedcipher.AES.new(self.key, mbedcipher.MODE_CBC, b'\x00'*16)
			#self._ccm_cipher_ctr.set_padding_mode(4)
			#self._ccm_cipher_cbc.set_padding_mode(4)
			return
		elif self.mode == cipherMODE.GCM:
			self._cipher = None #aad needed...

		else:
			raise Exception('Unknown cipher mode!')
		#self._cipher.set_padding_mode(4)
		
	def encrypt(self, data, aad = None):
		if self.mode == cipherMODE.CCM:
			return self.__ccm_encrypt(data, aad)
		elif self.mode == cipherMODE.GCM:
			self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_GCM, self.IV, aad)
			return self._cipher.encrypt(data)
		
		res = self._cipher.encrypt(data)
		return res

	def decrypt(self, data, aad = None, mac = None):
		if self.mode == cipherMODE.CCM:
			return self.__ccm_decrypt(data, aad, mac)
		elif self.mode == cipherMODE.GCM:
			if self._cipher is None:
				self._cipher = mbedcipher.AES.new(self.key, mbedcipher.MODE_GCM, self.IV, aad)
			return self._cipher.decrypt(data, mac)
		
		res = self._cipher.decrypt(data)
		return res
	
	def __ccm_encrypt(self, plaintext, aad):
		q = 15 - len(self.IV)
		blockSize = 16 # For AES...
		s0 = self._ccm_cipher_ctr.encrypt(b'\x00'*16) # For mac
		self.ctrint += 1
		self._ccm_cipher_ctr = mbedcipher.AES.new(self.key, mbedcipher.MODE_CTR, self.ctrint.to_bytes(self.ctrlen, byteorder='big', signed = False))

		c = self._ccm_cipher_ctr.encrypt(plaintext)
		
		# Mac
		pLen = len(plaintext)
		aadLen = len(aad)
		flags = (64 * (aadLen > 0) + 8 * ((self.segment_size - 2) // 2) + (q - 1))
		b0 = struct.pack("B", flags) + self.IV +  pLen.to_bytes(q, 'big')
		
		assocLenEncoded = b''
		if aadLen > 0:
			if aadLen < (2 ** 16 - 2 ** 8):
				encSize = 2
			elif aadLen < (2 ** 32):
				assocLenEncoded = b'\xFF\xFE'
				encSize = 4
			else:
				assocLenEncoded = b'\xFF\xFF'
				encSize = 8
			
			assocLenEncoded += aadLen.to_bytes(encSize, 'big')
			
		
		aadPadded =  assocLenEncoded + aad 
		#print(f"aad Format before pad: {len(aadPadded)}" )
		aadPad = b''
		if len(aadPadded) % blockSize != 0:
			#print("need to padd aad")
			aadPad =  b'\x00'*(blockSize - (len(aadPadded) % blockSize))
		
		aadPadded += aadPad
		ptxtPadded = plaintext 
		#ptxt padding
		ptxtPad = b''
		if (pLen % blockSize) != 0:
			#print("Should pad ptxt")
			ptxtPad = b'\x00'*(blockSize - (pLen % blockSize))
		
		ptxtPadded += ptxtPad
		
		macData = b0  + aadPadded + ptxtPadded
		#print(f"MAC input {macData}")
		t = self._ccm_cipher_cbc.encrypt(macData)
		t = t[-16:]
		tag = bytes([a ^ b for (a,b) in zip(t,s0)])[:self.segment_size] 
		return (c, tag)
	
	def __ccm_decrypt(self, ciphertext, aad, macvalue):
		q = 15 - len(self.IV) 
		s0 = self._ccm_cipher_ctr.encrypt(b'\x00'*16) # For mac
		
		self.ctrint += 1
		self._ccm_cipher_ctr = mbedcipher.AES.new(self.key, mbedcipher.MODE_CTR, self.ctrint.to_bytes(self.ctrlen, byteorder='big', signed = False))
		plaintext = self._ccm_cipher_ctr.encrypt(ciphertext)
		pLen = len(plaintext)
		aadLen = len(aad)
		flags = (64 * (aadLen > 0) + 8 * ((self.segment_size - 2) // 2) + (q - 1))
		b0 = struct.pack("B", flags) + self.IV +  pLen.to_bytes(q, 'big')
		
		
		assocLenEncoded = b''
		if aadLen > 0:
			if aadLen < (2 ** 16 - 2 ** 8):
				encSize = 2
			elif aadLen < (2 ** 32):
				assocLenEncoded = b'\xFF\xFE'
				encSize = 4
			else:
				assocLenEncoded = b'\xFF\xFF'
				encSize = 8
			
			assocLenEncoded += aadLen.to_bytes(encSize, 'big')
			
		
		aadPadded =  assocLenEncoded + aad 
		aadPad = b''
		if len(aadPadded) % 16 != 0:
			aadPad =  b'\x00'*(16 - (len(aadPadded) % 16))
		
		aadPadded += aadPad
		ptxtPadded = plaintext 
		#ptxt padding
		ptxtPad = b''
		if pLen % 16 != 0:
			#print("Should pad ptxt")
			ptxtPad = b'\x00'*(16 - (pLen % 16))
		
		ptxtPadded += ptxtPad
		
		macData = b0  + aadPadded + ptxtPadded
		t = self._ccm_cipher_cbc.encrypt(macData)
		t = t[-16:]
		tag = bytes([a ^ b for (a,b) in zip(t,s0)])[:self.segment_size]
		
		#return plaintext

		## Attempt to secure comparison... Idea: hash expected and received macs and compare the result in constant time...
		## Ideally should be done with HMAC with a RANDOM KEY! Doesn't cost much on a performance level.
		## For now we use shake_128(SHA3 without a key)
		#print(f"received mac {macvalue} \nComputed {tag}")
		h1 = hashlib.sha256()
		h1.update(tag)
		digest1 = h1.digest() 
		
		h2 = hashlib.sha256() 
		h2.update(macvalue)
		digest2 = h2.digest()
		
		# Constant time comparison of hashes. Probably overkill here because of the randomization introduced by HMAC..
		result = 0
		for x, y in zip(digest1, digest2):
			result |= x ^ y
		
		#print(f"Reuslt {result}")
		
		if result != 0:
			raise ValueError("Incorrect MAC")
		else:
			return plaintext