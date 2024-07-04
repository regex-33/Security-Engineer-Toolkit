
import  unicrypto.backends.pure.external.DES.DES as _pyDES
from unicrypto.symmetric import symmetricBASE, cipherMODE, expand_DES_key

class DES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None):
		symmetricBASE.__init__(self, key, mode, IV)

	def setup_cipher(self):
		if len(self.key) == 7:
			self.key = expand_DES_key(self.key)

		if self.mode == cipherMODE.ECB:
			mode = _pyDES.ECB
		elif self.mode == cipherMODE.CBC:
			mode = _pyDES.CBC
		else:
			raise Exception('Unknown cipher mode!')
		
		self._cipher = _pyDES.des(self.key, mode, self.IV)

	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)

