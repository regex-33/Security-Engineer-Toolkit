
from mbedtls import cipher as mbedcipher
from unicrypto.symmetric import symmetricBASE, cipherMODE

class TDES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None):
		symmetricBASE.__init__(self, key, mode, IV)

	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = mbedcipher.DES3.new(self.key, mbedcipher.MODE_ECB, b'')
		elif self.mode == cipherMODE.CBC:
			self._cipher = mbedcipher.DES3.new(self.key, mbedcipher.MODE_CBC, self.IV)
		else:
			raise Exception('Unknown cipher mode!')
	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)