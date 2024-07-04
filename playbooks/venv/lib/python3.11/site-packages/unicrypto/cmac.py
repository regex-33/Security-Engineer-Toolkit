from unicrypto.symmetric import AES
from unicrypto.backends.cmac import CMAC

def AES_CMAC(K, M, length):
	return CMAC(K, M, length, AES)