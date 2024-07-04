import pytest
from unicrypto import hashlib
from unicrypto.pbkdf2 import pbkdf2

#https://www.ietf.org/rfc/rfc6070.txt
pbkdf2_sha1_test = [
	('password', 'salt', 1, 20, '0c60c80f961f0e71f3a9b524af6012062fe037a6'),
	('password', 'salt', 2, 20, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'),
	('password', 'salt', 4096, 20, '4b007901b765489abead49d926f721d065a429c1'),
	#('password', 'salt', 16777216, 20, 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984'), #takes too long
	('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt',4096, 25, '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'),
	('pass\0word', 'sa\0lt', 4096, 16, '56fa6aa75548099dcc37d7f03425e0c3'),
]


def pbkdf2_tester(hashobj, vector):
	for i, res in enumerate(vector):
		password, salt, iters, keylen, ciphertext = res
		password = password.encode()
		salt = salt.encode()
		ciphertext = bytes.fromhex(ciphertext)
			
		hashed_data = pbkdf2(password, salt, iters, keylen, digestmod = hashobj)
		if hashed_data != ciphertext:
			raise Exception('Digest mismatch! SHA1 %s Cipher: \r\n%s \r\nVector: \r\n%s' % (i, hashed_data, ciphertext))
			
	return True

def test_sha1():
	hashobj = hashlib.sha1
	pbkdf2_tester(hashobj, pbkdf2_sha1_test)
