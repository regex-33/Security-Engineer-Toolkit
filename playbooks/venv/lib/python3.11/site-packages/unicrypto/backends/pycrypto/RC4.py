
from Crypto.Cipher import ARC4 as _pyCryptoRC4
from unicrypto.symmetric import symmetricBASE, cipherMODE

class RC4(symmetricBASE):
	def __init__(self, key):
		symmetricBASE.__init__(self, key)
		
	def setup_cipher(self):
		self._cipher = _pyCryptoRC4.new(self.key)
		
	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)

