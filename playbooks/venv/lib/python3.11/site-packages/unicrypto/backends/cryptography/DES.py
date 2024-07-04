from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from unicrypto.symmetric import symmetricBASE, cipherMODE, expand_DES_key


class DES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, pad = None, padMode = None):
		self.encryptor = None
		self.decryptor = None
		symmetricBASE.__init__(self, key, mode, IV)
		

	def setup_cipher(self):
		if len(self.key) == 7:
			self.key = expand_DES_key(self.key)

		self.key = self.key*3 # since there is no single-des in this module
		if self.mode == cipherMODE.ECB:
			self.IV = modes.ECB()
		elif self.mode == cipherMODE.CBC:
			self.IV = modes.CBC(self.IV)
		else:
			raise Exception('Unknown cipher mode!')

		algorithm = algorithms.TripleDES(self.key)
		self._cipher = Cipher(algorithm, mode=self.IV, backend=default_backend())
		self.encryptor = self._cipher.encryptor()
		self.decryptor = self._cipher.decryptor()

	def encrypt(self, data):
		return self.encryptor.update(data)

	def decrypt(self, data):
		return self.decryptor.update(data)

