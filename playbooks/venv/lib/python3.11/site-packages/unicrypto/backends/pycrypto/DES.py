
from Crypto.Cipher import DES as _pyCryptoDES
from unicrypto.symmetric import symmetricBASE, cipherMODE, expand_DES_key

class DES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None):
		symmetricBASE.__init__(self, key, mode, IV)

	def setup_cipher(self):
		if len(self.key) == 7:
			self.key = expand_DES_key(self.key)
		if self.mode == cipherMODE.ECB:
			self._cipher = _pyCryptoDES.new(self.key)
		elif self.mode == cipherMODE.CBC:
			self._cipher = _pyCryptoDES.new(self.key, _pyCryptoDES.MODE_CBC, self.IV)
		else:
			raise Exception('Unknown cipher mode!')

	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)

