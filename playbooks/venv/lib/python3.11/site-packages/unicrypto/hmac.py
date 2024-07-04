from abc import ABC, abstractmethod

import hmac as __builtinHMAC
from unicrypto import hashlib
from unicrypto import logging

class hmacBASE():
	def __init__(self, key):
		self.digest_size = None
		self.block_size = None
		self.name = None
		self._key = key
		self._hash = None
		self.setup_hash()

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
	
	@abstractmethod
	def copy(self):
		raise NotImplementedError()
	
	@staticmethod
	def compare_digest(self, a, b):
		raise NotImplementedError()

def hmacselector(key:bytes,  msg:bytes = None, digestmod:str = ''):
	logging.debug('hmac using "builtin" for "%s"' % digestmod)
	return __builtinHMAC.new(key, msg, digestmod)

new = hmacselector
