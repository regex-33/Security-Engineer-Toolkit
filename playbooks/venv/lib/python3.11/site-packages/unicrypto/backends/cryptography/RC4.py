
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from unicrypto.symmetric import symmetricBASE, cipherMODE

class RC4(symmetricBASE):
	def __init__(self, key):
		self.encryptor = None
		self.decryptor = None
		symmetricBASE.__init__(self, key)
		
	def setup_cipher(self):
		algorithm = algorithms.ARC4(self.key)
		self._cipher = Cipher(algorithm, mode=None, backend=default_backend())
		self.encryptor = self._cipher.encryptor()
		self.decryptor = self._cipher.decryptor()

	def encrypt(self, data):
		return self.encryptor.update(data)
	def decrypt(self, data):
		return self.decryptor.update(data)