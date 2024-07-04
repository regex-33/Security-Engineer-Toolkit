import  unicrypto.backends.pure.external.DES.DES as _pyDES
from unicrypto.symmetric import symmetricBASE, cipherMODE, expand_DES_key


class TDES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, pad = None, padMode = None):
		symmetricBASE.__init__(self, key, mode, IV)
		if not isinstance(key, bytes):
			raise Exception('Key needs to be bytes!')

		self.mode = mode
		self.IV = IV
		self.pad = pad
		self.padMode = padMode

	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			mode = _pyDES.ECB
			self._cipher = _pyDES.triple_des(self.key, mode)
		elif self.mode == cipherMODE.CBC:
			mode = _pyDES.CBC
			self._cipher = _pyDES.triple_des(self.key, mode, self.IV, pad = None)
		else:
			raise Exception('Unknown cipher mode!')

	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)
