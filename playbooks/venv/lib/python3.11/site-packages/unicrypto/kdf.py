from unicrypto import hmac
from unicrypto.backends.kdf import KDF_CounterMode as KDF_CounterMode_inner

def KDF_CounterMode(KI, Label, Context, L):
	return KDF_CounterMode_inner(KI, Label, Context, L, hmac)
