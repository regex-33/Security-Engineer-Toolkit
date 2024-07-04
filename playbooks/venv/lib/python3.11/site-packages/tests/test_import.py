from unicrypto import get_cipher_by_name

def test_aes_mbedtls():
    obj = get_cipher_by_name('AES', 'mbedtls')
    if str(obj).find('unicrypto.backends.mbedtls.AES') == -1:
        raise Exception('Wrong backend selected!')

def test_aes_pycryptodome():
    obj = get_cipher_by_name('AES', 'pycryptodome')
    if str(obj).find('unicrypto.backends.pycryptodome.AES') == -1:
        raise Exception('Wrong backend selected!')

def test_aes_pycryptodome():
    obj = get_cipher_by_name('AES', 'pycryptodomex')
    if str(obj).find('unicrypto.backends.pycryptodomex.AES') == -1:
        raise Exception('Wrong backend selected!')

def test_aes_cryptography():
    obj = get_cipher_by_name('AES', 'cryptography')
    if str(obj).find('unicrypto.backends.cryptography.AES') == -1:
        raise Exception('Wrong backend selected!')

def test_aes_pure():
    obj = get_cipher_by_name('AES', 'pure')
    if str(obj).find('unicrypto.backends.pure.AES') == -1:
        raise Exception('Wrong backend selected!')

def test_rc4_mbedtls():
    obj = get_cipher_by_name('RC4', 'mbedtls')
    if str(obj).find('unicrypto.backends.mbedtls.RC4') == -1:
        raise Exception('Wrong backend selected!')

def test_rc4_pycryptodome():
    obj = get_cipher_by_name('RC4', 'pycryptodome')
    if str(obj).find('unicrypto.backends.pycryptodome.RC4') == -1:
        raise Exception('Wrong backend selected!')

def test_rc4_cryptography():
    obj = get_cipher_by_name('RC4', 'cryptography')
    if str(obj).find('unicrypto.backends.cryptography.RC4') == -1:
        raise Exception('Wrong backend selected!')

def test_rc4_pure():
    obj = get_cipher_by_name('RC4', 'pure')
    if str(obj).find('unicrypto.backends.pure.RC4') == -1:
        raise Exception('Wrong backend selected!')

def test_rc4_pycryptodomex():
    obj = get_cipher_by_name('RC4', 'pycryptodomex')
    if str(obj).find('unicrypto.backends.pycryptodomex.RC4') == -1:
        raise Exception('Wrong backend selected!')

def test_des_mbedtls():
    obj = get_cipher_by_name('DES', 'mbedtls')
    if str(obj).find('unicrypto.backends.mbedtls.DES') == -1:
        raise Exception('Wrong backend selected!')

def test_des_pycryptodome():
    obj = get_cipher_by_name('DES', 'pycryptodome')
    if str(obj).find('unicrypto.backends.pycryptodome.DES') == -1:
        raise Exception('Wrong backend selected!')

def test_des_cryptography():
    obj = get_cipher_by_name('DES', 'cryptography')
    if str(obj).find('unicrypto.backends.cryptography.DES') == -1:
        raise Exception('Wrong backend selected!')

def test_des_pure():
    obj = get_cipher_by_name('DES', 'pure')
    if str(obj).find('unicrypto.backends.pure.DES') == -1:
        raise Exception('Wrong backend selected!')

def test_des_pycryptodomex():
    obj = get_cipher_by_name('DES', 'pycryptodomex')
    if str(obj).find('unicrypto.backends.pycryptodomex.DES') == -1:
        raise Exception('Wrong backend selected!')
    

def test_tdes_mbedtls():
    obj = get_cipher_by_name('TDES', 'mbedtls')
    if str(obj).find('unicrypto.backends.mbedtls.TDES') == -1:
        raise Exception('Wrong backend selected!')

def test_tdes_pycryptodome():
    obj = get_cipher_by_name('TDES', 'pycryptodome')
    if str(obj).find('unicrypto.backends.pycryptodome.TDES') == -1:
        raise Exception('Wrong backend selected!')

def test_tdes_cryptography():
    obj = get_cipher_by_name('TDES', 'cryptography')
    if str(obj).find('unicrypto.backends.cryptography.TDES') == -1:
        raise Exception('Wrong backend selected!')

def test_tdes_pure():
    obj = get_cipher_by_name('TDES', 'pure')
    if str(obj).find('unicrypto.backends.pure.TDES') == -1:
        raise Exception('Wrong backend selected!')

def test_tdes_pycryptodomex():
    obj = get_cipher_by_name('TDES', 'pycryptodomex')
    if str(obj).find('unicrypto.backends.pycryptodomex.TDES') == -1:
        raise Exception('Wrong backend selected!')

def test_rc4_mbedtls():
    obj = get_cipher_by_name('RC4', 'mbedtls')
    if str(obj).find('unicrypto.backends.mbedtls.RC4') == -1:
        raise Exception('Wrong backend selected!')

def test_rc4_pycryptodome():
    obj = get_cipher_by_name('RC4', 'pycryptodome')
    if str(obj).find('unicrypto.backends.pycryptodome.RC4') == -1:
        raise Exception('Wrong backend selected!')

def test_rc4_cryptography():
    obj = get_cipher_by_name('RC4', 'cryptography')
    if str(obj).find('unicrypto.backends.cryptography.RC4') == -1:
        raise Exception('Wrong backend selected!')

def test_rc4_pure():
    obj = get_cipher_by_name('RC4', 'pure')
    if str(obj).find('unicrypto.backends.pure.RC4') == -1:
        raise Exception('Wrong backend selected!')

def test_rc4_pycryptodomex():
    obj = get_cipher_by_name('RC4', 'pycryptodomex')
    if str(obj).find('unicrypto.backends.pycryptodomex.RC4') == -1:
        raise Exception('Wrong backend selected!')


if __name__ == '__main__':
    test_aes_mbedtls()