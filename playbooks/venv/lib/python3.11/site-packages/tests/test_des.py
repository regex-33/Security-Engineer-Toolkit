
import pytest
from unicrypto import get_cipher_by_name
from unicrypto import symmetric

des_ecb = [
	('0000000000000000', '0000000000000000', '8CA64DE9C1B123A7'),
	('FFFFFFFFFFFFFFFF', 'FFFFFFFFFFFFFFFF', '7359B2163E4EDC58'),
	('3000000000000000', '1000000000000001', '958E6E627A05557B'),
	('1111111111111111', '1111111111111111', 'F40379AB9E0EC533'),
	('0123456789ABCDEF', '1111111111111111', '17668DFC7292532D'),
	('1111111111111111', '0123456789ABCDEF', '8A5AE1F81AB8F2DD'),
	('FEDCBA9876543210', '0123456789ABCDEF', 'ED39D950FA74BCC4'),
	('FEDCBA9876543210', '0123456789ABCDEF0123456789ABCDEF', 'ED39D950FA74BCC4ED39D950FA74BCC4'),

]

des_cbc = [
	('0123456789abcdef','fedcba9876543210' , '37363534333231204E6F77206973207468652074696D6520', 'ccd173ffab2039f4acd8aefddfd8a1eb468e91157888ba68'),
]


def ecb_enc(cipherobj:symmetric.symmetricBASE, vector):
	for i, res in enumerate(vector):
		key, plaintext, ciphertext = res
		plaintext = bytes.fromhex(plaintext)
		key = bytes.fromhex(key)
		ciphertext = bytes.fromhex(ciphertext)

		ctx = cipherobj(key)
		enc_data = ctx.encrypt(plaintext)
		if enc_data != ciphertext:
			raise Exception('Ciphertext doesnt match to vector! DES %s Cipher: \r\n%s \r\nVector: \r\n%s' % (i, enc_data, ciphertext))
			
		ctx = cipherobj(key)
		dec_data = ctx.decrypt(enc_data)
		if dec_data != plaintext:
			raise Exception('Decrypted data doesnt match plaintext! DES-ECB Cipher: \r\n%s \r\nPlaintext: \r\n%s' % (dec_data.hex(), plaintext.hex()))

	return True
	
def cbc_enc(cipherobj:symmetric.symmetricBASE, vector):
	for i, res in enumerate(vector):
		key, iv, plaintext, ciphertext = res
		plaintext = bytes.fromhex(plaintext)
		key = bytes.fromhex(key)
		ciphertext = bytes.fromhex(ciphertext)
		iv = bytes.fromhex(iv)

		ctx = cipherobj(key, symmetric.MODE_CBC, iv)
		enc_data = ctx.encrypt(plaintext)
		if enc_data != ciphertext:
			raise Exception('Ciphertext doesnt match to vector! DES %s Cipher: \r\n%s \r\nVector: \r\n%s' % (i, enc_data, ciphertext))

		ctx = cipherobj(key, symmetric.MODE_CBC, iv)
		dec_data = ctx.decrypt(enc_data)
		if dec_data != plaintext:
			raise Exception('Decrypted data doesnt match plaintext! DES-CBC Cipher: \r\n%s \r\nPlaintext: \r\n%s' % (dec_data.hex(), plaintext.hex()))

	return True

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('DES', 'pure')])
def test_ecb(cipherobj):
	from unicrypto.backends.pure import DES
	assert isinstance(cipherobj, DES)
	ecb_enc(cipherobj, des_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('DES', 'pure')])
def test_cbc(cipherobj):
	cbc_enc(cipherobj, des_cbc)

#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('DES', 'crypto')])
#def test_ecb(cipherobj):
#	ecb_enc(cipherobj, des_ecb)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('DES', 'crypto')])
#def test_cbc(cipherobj):
#	cbc_enc(cipherobj, des_cbc)


@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('DES', 'pycryptodome')])
def test_ecb(cipherobj):
	ecb_enc(cipherobj, des_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('DES', 'pycryptodome')])
def test_cbc(cipherobj):
	cbc_enc(cipherobj, des_cbc)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('DES', 'cryptography')])
def test_ecb(cipherobj):
	ecb_enc(cipherobj, des_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('DES', 'cryptography')])
def test_cbc(cipherobj):
	cbc_enc(cipherobj, des_cbc)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('DES', 'mbedtls')])
def test_ecb(cipherobj):
	ecb_enc(cipherobj, des_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('DES', 'mbedtls')])
def test_cbc(cipherobj):
	cbc_enc(cipherobj, des_cbc)

