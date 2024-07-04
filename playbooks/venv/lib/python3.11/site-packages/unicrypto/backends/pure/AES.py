import io
import struct
from unicrypto.symmetric import symmetricBASE, cipherMODE
from unicrypto.backends.pure.external.AES import AESModeOfOperationCBC,\
    AESModeOfOperationECB, AESModeOfOperationCTR, AESModeOfOperationCFB,\
	AESModeOfOperationOFB, encrypt_stream, decrypt_stream, PADDING_NONE,\
	Counter, Encrypter
from unicrypto import hashlib

class AES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, segment_size = 8):
		
		self._ccm_cipher_ctr = None
		self._ccm_cipher_cbc = None
		symmetricBASE.__init__(self, key, mode, IV, segment_size=segment_size)
	
	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = AESModeOfOperationECB(self.key)
		elif self.mode == cipherMODE.CBC:
			self._cipher = AESModeOfOperationCBC(self.key, iv = self.IV)
		elif self.mode == cipherMODE.CTR:
			self._cipher = AESModeOfOperationCTR(self.key, counter = Counter(int.from_bytes(self.IV, byteorder='big', signed=False)))
		elif self.mode == cipherMODE.CFB:
			self._cipher = AESModeOfOperationCFB(self.key, iv = self.IV, segment_size = self.segment_size//8)
		elif self.mode == cipherMODE.OFB:
			self._cipher = AESModeOfOperationOFB(self.key, iv = self.IV)
		elif self.mode == cipherMODE.CCM:
			if self.segment_size not in (4, 6, 8, 10, 12, 14, 16):
				raise ValueError("Parameter 'mac_len' must be even and in the range 4..16 (not %d)" % self.segment_size)
			if not (self.IV and 7 <= len(self.IV) <= 13):
				raise ValueError("Length of parameter 'nonce' must be in the range 7..13 bytes")

			q = 15 - len(self.IV)
			t_nonce = struct.pack("B", q - 1) + self.IV
			t_noncepad = b'\x00'*(16 - (len(t_nonce) % 16)) # 16 is the blocksize
			t_nonce += t_noncepad
			ctr_start = Counter(int.from_bytes(t_nonce, byteorder='big', signed=False))
			self._ccm_cipher_ctr = AESModeOfOperationCTR(self.key, ctr_start)
			self._ccm_cipher_cbc = Encrypter(AESModeOfOperationCBC(self.key, iv=b'\x00'*16), padding = PADDING_NONE) # 16 is the blocksize
		elif self.mode == cipherMODE.GCM:
			from unicrypto.backends.pure.external.AES.AESGCM import AES_GCM
			self._cipher = AES_GCM(self.key)

		else:
			raise Exception('Unknown cipher mode!')

	def encrypt(self, data, aad = None):
		if self.mode == cipherMODE.CCM:
			return self.__ccm_encrypt(data, aad)
		
		if self.mode == cipherMODE.GCM:
			return self._cipher.encrypt(self.IV, data, aad)

		if self.mode != cipherMODE.CFB:
			in_buff = io.BytesIO(data)
			out_buff = io.BytesIO()
			encrypt_stream(self._cipher, in_buff, out_buff, padding = PADDING_NONE)
			out_buff.seek(0)
			return out_buff.read()
		else:
			return self._cipher.encrypt(data)

	def decrypt(self, data, aad = None, mac = None):
		if self.mode == cipherMODE.CCM:
			return self.__ccm_decrypt(data, aad, mac)
		
		if self.mode == cipherMODE.GCM:
			return self._cipher.decrypt(self.IV, data, mac, aad)

		if self.mode != cipherMODE.CFB:
			in_buff = io.BytesIO(data)
			out_buff = io.BytesIO()
			decrypt_stream(self._cipher, in_buff, out_buff, padding = PADDING_NONE)
			out_buff.seek(0)
			return out_buff.read()
		else:
			return self._cipher.decrypt(data)
	
	def __ccm_encrypt(self, plaintext, aad):
		q = 15 - len(self.IV)
		blockSize = 16 # For AES...
		s0 = self._ccm_cipher_ctr.encrypt(b'\x00'*16) # For mac
		#print(f"My s0 {s0}")
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
		t = self._ccm_cipher_cbc.feed(macData)
		t += self._ccm_cipher_cbc.feed()
		t = t[-16:]
		tag = bytes([a ^ b for (a,b) in zip(t,s0)])[:self.segment_size] 
		return (c, tag)
	
	def __ccm_decrypt(self, ciphertext, aad, macvalue):
		#print('aad: %s' % aad)
		#print('mac: %s' % macvalue)
		# Decrytion: in CTR Encrypt == Decrypt				
		# Decryption
		q = 15 - len(self.IV) 
		s0 = self._ccm_cipher_ctr.encrypt(b'\x00'*16) # For mac
		#print(f"My s0 {s0}")
		plaintext = self._ccm_cipher_ctr.encrypt(ciphertext)
		#print(f"recoverd plaintex {plaintext}")
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
		if len(aadPadded) % 16 != 0:
			#print("need to padd aad")
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
		#t = mac.encrypt(macData)[-16:]
		t = self._ccm_cipher_cbc.feed(macData)
		t += self._ccm_cipher_cbc.feed()
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
	