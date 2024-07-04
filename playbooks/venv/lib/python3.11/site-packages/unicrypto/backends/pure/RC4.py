
from unicrypto.backends.pure.external.RC4.RC4 import RC4 as _pureRC4
from unicrypto.symmetric import symmetricBASE, cipherMODE

class RC4(symmetricBASE):
	def __init__(self, key):
		symmetricBASE.__init__(self, key)
		
	def setup_cipher(self):		
		self._cipher = _pureRC4(self.key)

	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)

