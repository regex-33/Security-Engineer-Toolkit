
from Cryptodome.Cipher import DES3
from unicrypto.symmetric import symmetricBASE, cipherMODE

class TDES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None):
		symmetricBASE.__init__(self, key, mode, IV)

	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = DES3.new(self.key, DES3.MODE_ECB)
		elif self.mode == cipherMODE.CBC:
			self._cipher = DES3.new(self.key, DES3.MODE_CBC, iv=self.IV)
		else:
			raise Exception('Unknown cipher mode!')
		
	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)

