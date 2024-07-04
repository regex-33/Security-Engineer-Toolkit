from abc import ABC, abstractmethod
import hashlib as __builtinHashlib
from unicrypto import logging

class hashBASE():
	def __init__(self, data:bytes):
		self._hash = None
		self.setup_hash()

		if data is not None:
			self._hash.update(data)

	@abstractmethod
	def setup_hash(self):
		#create the hash object here
		raise NotImplementedError()

	@abstractmethod
	def update(self, data):
		raise NotImplementedError()

	@abstractmethod
	def digest(self):
		raise NotImplementedError()

	@abstractmethod
	def hexdigest(self):
		raise NotImplementedError()

def hashselector(name:str, data:bytes = b''):
	if name.lower() == 'md4':
		logging.debug('hashlib using "pure" for "%s"' % name)
		from unicrypto.backends.pure.MD4 import MD4
		return MD4(data)

	if name.lower() in __builtinHashlib.algorithms_available:
		logging.debug('hashlib using "builtin" for "%s"' % name)
		return __builtinHashlib.new(name, data)
	
	raise NotImplementedError('Algorithm "%s" is not implemented!' % name)

def md4hash(data:bytes = b''):
	return hashselector('md4', data)


new = hashselector
md4 = md4hash
md5 = __builtinHashlib.md5
sha1 = __builtinHashlib.sha1
sha224 = __builtinHashlib.sha224
sha256 = __builtinHashlib.sha256
sha384 = __builtinHashlib.sha384
sha512 = __builtinHashlib.sha512





