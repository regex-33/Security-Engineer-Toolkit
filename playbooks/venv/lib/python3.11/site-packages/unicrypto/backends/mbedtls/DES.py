
from mbedtls import cipher as mbedcipher
from unicrypto.symmetric import symmetricBASE, cipherMODE, expand_DES_key

class DES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None):
		symmetricBASE.__init__(self, key, mode, IV)

	def setup_cipher(self):
		if len(self.key) == 7:
			self.key = expand_DES_key(self.key)
		if self.mode == cipherMODE.ECB:
			self._cipher = mbedcipher.DES.new(self.key, mbedcipher.MODE_ECB, b'')
		elif self.mode == cipherMODE.CBC:
			self._cipher = mbedcipher.DES.new(self.key, mbedcipher.MODE_CBC, self.IV)
		else:
			raise Exception('Unknown cipher mode!')
	
	def __encrypt_inner(self, data):
		res = self._cipher.encrypt(data)
		return res

	def encrypt(self, data):
		res = b''
		if len(data) > self._cipher.block_size:
			for dc in [data[i:i + self._cipher.block_size] for i in range(0, len(data), self._cipher.block_size)]:
				res += self.__encrypt_inner(dc)
		else:
			res = self.__encrypt_inner(data)
		return res

	def __decrypt_inner(self, data):
		res = self._cipher.decrypt(data)
		return res
	
	def decrypt(self, data):
		res = b''
		if len(data) > self._cipher.block_size:
			for dc in [data[i:i + self._cipher.block_size] for i in range(0, len(data), self._cipher.block_size)]:
				res += self.__decrypt_inner(dc)
		else:
			res = self.__decrypt_inner(data)
		return res