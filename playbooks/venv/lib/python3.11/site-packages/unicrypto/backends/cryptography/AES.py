from unicrypto.symmetric import symmetricBASE, cipherMODE
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from unicrypto.symmetric import symmetricBASE, cipherMODE

class AES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, pad = None, segment_size = 128):
		self.encryptor = None
		self.decryptor = None
		symmetricBASE.__init__(self, key, mode, IV, segment_size=segment_size)
		

	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self.IV = modes.ECB()
		elif self.mode == cipherMODE.CBC:
			self.IV = modes.CBC(self.IV)
		elif self.mode == cipherMODE.CTR:
			self.IV = modes.CTR(self.IV)
		elif self.mode == cipherMODE.CFB:
			if self.segment_size == 8:
				self.IV = modes.CFB8(self.IV)
			elif self.segment_size == 128:
				self.IV = modes.CFB(self.IV)
		elif self.mode == cipherMODE.OFB:
			self.IV = modes.OFB(self.IV)
		
		elif self.mode == cipherMODE.CCM:
			from cryptography.hazmat.primitives.ciphers.aead import AESCCM
			self._cipher = AESCCM(self.key, tag_length=self.segment_size)
			return
		elif self.mode == cipherMODE.GCM:
			from cryptography.hazmat.primitives.ciphers.aead import AESGCM
			self._cipher = AESGCM(self.key)
			return
		else:
			raise Exception('Unknown cipher mode!')

		algorithm = algorithms.AES(self.key)
		self._cipher = Cipher(algorithm, mode=self.IV, backend=default_backend())
		self.encryptor = self._cipher.encryptor()
		self.decryptor = self._cipher.decryptor()

	def encrypt(self, data, aad = None):
		if self.mode == cipherMODE.CCM or self.mode == cipherMODE.GCM:
			res = self._cipher.encrypt(self.IV, data, aad)
			return res[:-16], res[-16:]
		else:
			return self.encryptor.update(data)
	
	def decrypt(self, data, aad = None, mac = None):
		if self.mode == cipherMODE.CCM or self.mode == cipherMODE.GCM:
			return self._cipher.decrypt(self.IV, data+mac, aad)
		else:
			return self.decryptor.update(data)