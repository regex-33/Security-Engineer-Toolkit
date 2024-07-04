import importlib
import importlib.util
import logging

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

#https://stackoverflow.com/questions/8790003/dynamically-import-a-method-in-a-file-from-a-string
def import_from(module, name):
	module = __import__(module, fromlist=[name])
	return getattr(module, name)

pref_to_module = {
	'mbedtls' : 'mbedtls',
	'cryptography' : 'cryptography',
	'pyCryptodomex': 'Cryptodome',
	# see https://github.com/Legrandin/pycryptodome/blob/master/Changelog.rst#30-24-june-2014
	'pyCryptodome': 'Crypto.Cipher.Salsa20',
	'pyCrypto' : 'Crypto.Random.OSRNG'
}

# preferred modules for each cipher, in order of preferance
preftable = {
	'DES' : ['pyCryptodomex','pyCryptodome','cryptography','pyCrypto','mbedtls','pure'],
	'TDES': ['pyCryptodomex','pyCryptodome','cryptography','pyCrypto','mbedtls','pure'],
	'AES' : ['pyCryptodomex','pyCryptodome','cryptography','pyCrypto','mbedtls','pure'],
	'RC4' : ['pyCryptodomex','pyCryptodome','cryptography','pyCrypto','mbedtls','pure'],
}

available_modules = {
	'DES' : ['pure'],
	'TDES' : ['pure'],
	'AES' : ['pure'],
	'RC4' : ['pure'],
}

override_library = None

for prefname in pref_to_module:
	try:
		importlib.util.find_spec(pref_to_module[prefname])
	except ModuleNotFoundError:
		continue
	
	if importlib.util.find_spec(pref_to_module[prefname]) is not None:
		for k in available_modules:
			available_modules[k].append(prefname)


def get_cipher_by_name(ciphername, cryptolibname):
	logging.debug('symmetric using "%s" for "%s"' % (cryptolibname, ciphername))
	moduleName = 'unicrypto.backends.%s.%s' % (cryptolibname.lower(), ciphername)
	return import_from(moduleName , ciphername)


def get_preferred_cipher(ciphername):
	if override_library is None:
		if ciphername not in preftable:
			raise Exception('Cipher "%s" is not supported!' % ciphername)
		#print('available_modules %s' % available_modules)
		possible_prefmodule = list(set(preftable[ciphername]).intersection(set(available_modules[ciphername])))
		#print('possible_prefmodule %s' % possible_prefmodule)
		selected_module = None
		for moduleName in preftable[ciphername]:
			if moduleName in possible_prefmodule:
				selected_module = moduleName
				break

		if selected_module is None:
			raise Exception('Could not find any modules to load cipher "%s"' % ciphername)
	else:
		selected_module = override_library

	#print('Preferred module selected for cipher %s is %s' % (ciphername, selected_module))
	return get_cipher_by_name(ciphername, selected_module)

def use_library(libname):
	global override_library
	override_library = libname
