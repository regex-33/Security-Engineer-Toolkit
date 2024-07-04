
from Crypto.Cipher import DES3 as _pyCryptoDES3
from unicrypto.symmetric import symmetricBASE, cipherMODE

class TDES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, pad = None, padMode = None):
		symmetricBASE.__init__(self, key, mode, IV)
		
	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = _pyCryptoDES3.new(self.key, _pyCryptoDES3.MODE_ECB)
		
		elif self.mode == cipherMODE.CBC:
			self._cipher = _pyCryptoDES3.new(self.key, _pyCryptoDES3.MODE_CBC, self.IV)
		else:
			raise Exception('Unknown cipher mode!')
		
	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)

