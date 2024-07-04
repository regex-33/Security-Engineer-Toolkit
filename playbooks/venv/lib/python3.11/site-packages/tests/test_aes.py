
import pytest
from unicrypto import get_cipher_by_name
from unicrypto import symmetric

# NOTE: python-mbedtls has issues with CFB and GCM modes, issue has been sent to the maintainer
# old crypto backend is not supported anymore

# https://github.com/weidai11/cryptopp/blob/master/TestVectors/aes.txt

aes_128_ecb = [
	#plaintext, key, ciphertext
	('6bc1bee22e409f96e93d7e117393172a', '2b7e151628aed2a6abf7158809cf4f3c', '3ad77bb40d7a3660a89ecaf32466ef97'),
	('ae2d8a571e03ac9c9eb76fac45af8e51', '2b7e151628aed2a6abf7158809cf4f3c', 'f5d3d58503b9699de785895a96fdbaaf'),
	('30c81c46a35ce411e5fbc1191a0a52ef', '2b7e151628aed2a6abf7158809cf4f3c', '43b1cd7f598ece23881b00e3ed030688'),
	('f69f2445df4f9b17ad2b417be66c3710', '2b7e151628aed2a6abf7158809cf4f3c', '7b0c785e27e8ad3f8223207104725dd4'),
]
aes_192_ecb = [
	('6bc1bee22e409f96e93d7e117393172a', '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'bd334f1d6e45f25ff712a214571fa5cc'),
	('ae2d8a571e03ac9c9eb76fac45af8e51', '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', '974104846d0ad3ad7734ecb3ecee4eef'),
	('30c81c46a35ce411e5fbc1191a0a52ef', '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'ef7afd2270e2e60adce0ba2face6444e'),
	('f69f2445df4f9b17ad2b417be66c3710', '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', '9a4b41ba738d6c72fb16691603c18e0e'),
]
aes_256_ecb = [
	('6bc1bee22e409f96e93d7e117393172a', '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'f3eed1bdb5d2a03c064b5a7e3db181f8'),
	('ae2d8a571e03ac9c9eb76fac45af8e51', '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', '591ccb10d410ed26dc5ba74a31362870'),
	('30c81c46a35ce411e5fbc1191a0a52ef', '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'b6ed21b99ca6f4f9f153e7b1beafed1d'),
	('f69f2445df4f9b17ad2b417be66c3710', '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', '23304b7a39f9f3ff067d8d8f9e24ecc7'),
]

aes_ecb_long = [
	('006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c371000'*8,'2b7e151628aed2a6abf7158809cf4f3c','84C6CBDC2B5A39985774B23BAB066A6AF8CB66C08E4F058E5D3E7C351EA845CEC7B209210EE7EFD38269628687F21CB9BCEA349DC0418ADBA2BF2364DF4DB1A11AD84CF6A422CE95C37B2CF81196245CD857D0B954B83985C1888230F3C301847AAF714253EF768C17E89E4F5513DBD5BEE1266A2B2D7063CE3D0BA8716252C5BCBB9922CD46F374B52FDFF1FEBF155FF4AFEE18788999BC74234A3FFBA7B2858BB2552F172E56EC47456878440ABB5ADAE49941C1E43616AC5D6E31A011611B829F6A77BE1F50754F81F35D24ED89FDE804B17363F9A81C3F12AE067FDD41A2984912CAE1926C5FB3AC18E541FA4AD1E171888E61428F2A8F2E981AE16D0D4E41D33E5E675F446DAE0F454FC4CA056F41F3CC4744A9E948428B2280F96663B7230C09692503C95B3E34F8DE8DF23157F45BDF689B258D994D9E6CE5D4DD6BDB96763CCC41DBBE57A4778D5A9E90226D614C335E44CA8AB41EFEA898BC170C65412F77194A43A1305EF23AC70B059E6E047796EF518D7696BC3DAD5E2634F92DD1C90D206A2B6D3A7CE88668BEAD64614E9000ACFBA79EB3601606214E21E08F14CE77E36BB66FE4A0FCD2A21BCAA2391A9C2016AC3BC7CDF1438EB6DD26696644583E2B0A0C68629D736F6723DF66859CF80B4E5B5C5BF03F334D65C48DB3B2660E2CE33B510FD60C912B85D16AEE7CDBFDF6285B0A77BAE07D987F9CE172A548E6BF0A30CF099AA82BE0A25E0E8919')
]

aes_cbc_128 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','2b7e151628aed2a6abf7158809cf4f3c','7649abac8119b246cee98e9b12e9197d','000102030405060708090a0b0c0d0e0f'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','2b7e151628aed2a6abf7158809cf4f3c','5086cb9b507219ee95db113a917678b2','000102030405060708090a0b0c0d0e0f'),
	('30c81c46a35ce411e5fbc1191a0a52ef','2b7e151628aed2a6abf7158809cf4f3c','73bed6b8e3c1743b7116e69e22229516','000102030405060708090a0b0c0d0e0f'),
	('f69f2445df4f9b17ad2b417be66c3710','2b7e151628aed2a6abf7158809cf4f3c','3ff1caa1681fac09120eca307586e1a7','000102030405060708090a0b0c0d0e0f'),
]

aes_cbc_192 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','4f021db243bc633d7178183a9fa071e8','000102030405060708090a0b0c0d0e0f'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','b4d9ada9ad7dedf4e5e738763f69145a','000102030405060708090a0b0c0d0e0f'),
	('30c81c46a35ce411e5fbc1191a0a52ef','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','571b242012fb7ae07fa9baac3df102e0','000102030405060708090a0b0c0d0e0f'),
	('f69f2445df4f9b17ad2b417be66c3710','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','08b0e27988598881d920a9e64f5615cd','000102030405060708090a0b0c0d0e0f'),
]

aes_cbc_256 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','f58c4c04d6e5f1ba779eabfb5f7bfbd6','000102030405060708090a0b0c0d0e0f'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','9cfc4e967edb808d679f777bc6702c7d','000102030405060708090a0b0c0d0e0f'),
	('30c81c46a35ce411e5fbc1191a0a52ef','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','39f23369a9d9bacfa530e26304231461','000102030405060708090a0b0c0d0e0f'),
	('f69f2445df4f9b17ad2b417be66c3710','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','b2eb05e2c39be9fcda6c19078c6a9d1b','000102030405060708090a0b0c0d0e0f'),
]

aes_cbc_long = [
	('006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c371000'*8,'2b7e151628aed2a6abf7158809cf4f3c','6544CCA076C4D67C1A69DD7E504C6586FBD22912505E187D8628E19FA067D6C339D078E3032B8596DA74BB0E23434F83E153D5ACD5DEF7D264F58EC685317BF50C93430791718D6E09CCC4804FFE4EEB5C6AD8E9B5DFD456EDE81081627A97FC2FAE9F1955377D7774E68EAB541B20CE3C915185BCA208EE08428C400043F2DC90B0390756762C9271946FCE214B9576F74399E466DAC48C6DD10B420F302941DCC27D55CF1FB59D71954950CAD893FFFA70970D128C77BFA34F3C84B0B64A01194A086ACDD9847D6B91B7F870D0E7591CA07F0B407005F1473C37A648F6E18044336F30418BA43FD7AA5B5BAE01A0E33B1EDA4487730F043E202DE44CB901BD3AED13D790D05F325C414831EB601BD918678C1B8E116877CE1167F87204B49619D323713F95C04CA9621FDCF44BD21C5E36A299C486C8FC0D3043EDFF424B9A7AA5500DC3BD7BF6FAB256E6B45B458058DC933F1FF8C5E841BFC7F405761E14B12B48C1C108F33BF8D65BB8DBB9ED7E92398E779333730F4C68922AA76409E842E76B649B981B8269186220ACFF9DFA198D62CBF4CFA0FE05C1427CE63A345A61FE460D14EF25D7A89E2E228B415757B4E4110B6AFA7D85D48C3BCF184FDD7366F06D9E3D29896B0D3C0D83FCFA881E6EC5F29B0294628EDFF284E58B7BE19D37A6B28D70DC0F165A4B60CE5536D76D1A71849C36B0837E4E5082A05208CEEB320C57F0F5B86DC3CAAC8A32DEA9552D','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
]

aes_cfb_feedbacksize_1 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172aae2d','2b7e151628aed2a6abf7158809cf4f3c','3b79424c9c0dd436bace9e0ed4586a4f32b9','000102030405060708090a0b0c0d0e0f'),
	('6bc1bee22e409f96e93d7e117393172aae2d','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','cda2521ef0a905ca44cd057cbf0d47a0678a','000102030405060708090a0b0c0d0e0f'),
	('6bc1bee22e409f96e93d7e117393172aae2d','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','dc1f1a8520a64db55fcc8ac554844e889700','000102030405060708090a0b0c0d0e0f'),
]

aes_cfb_128_feedbacksize_16 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','2b7e151628aed2a6abf7158809cf4f3c','3b3fd92eb72dad20333449f8e83cfb4a','000102030405060708090a0b0c0d0e0f'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','2b7e151628aed2a6abf7158809cf4f3c','c8a64537a0b3a93fcde3cdad9f1ce58b','000102030405060708090a0b0c0d0e0f'),
	('30c81c46a35ce411e5fbc1191a0a52ef','2b7e151628aed2a6abf7158809cf4f3c','26751f67a3cbb140b1808cf187a4f4df','000102030405060708090a0b0c0d0e0f'),
	('f69f2445df4f9b17ad2b417be66c3710','2b7e151628aed2a6abf7158809cf4f3c','c04b05357c5d1c0eeac4c66f9ff7f2e6','000102030405060708090a0b0c0d0e0f'),
]

aes_cfb_192_feedbacksize_16 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','cdc80d6fddf18cab34c25909c99a4174','000102030405060708090a0b0c0d0e0f'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','67ce7f7f81173621961a2b70171d3d7a','000102030405060708090a0b0c0d0e0f'),
	('30c81c46a35ce411e5fbc1191a0a52ef','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','2e1e8a1dd59b88b1c8e60fed1efac4c9','000102030405060708090a0b0c0d0e0f'),
	('f69f2445df4f9b17ad2b417be66c3710','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','c05f9f9ca9834fa042ae8fba584b09ff','000102030405060708090a0b0c0d0e0f'),
]

aes_cfb_256_feedbacksize_16 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','dc7e84bfda79164b7ecd8486985d3860','000102030405060708090a0b0c0d0e0f'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','39ffed143b28b1c832113c6331e5407b','000102030405060708090a0b0c0d0e0f'),
	('30c81c46a35ce411e5fbc1191a0a52ef','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','df10132415e54b92a13ed0a8267ae2f9','000102030405060708090a0b0c0d0e0f'),
	('f69f2445df4f9b17ad2b417be66c3710','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','75a385741ab9cef82031623d55b1e471','000102030405060708090a0b0c0d0e0f'),
]

aes_cfb_long = [
	('006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'*11,'2b7e151628aed2a6abf7158809cf4f3c','ECE71ECD7A4E3C2F643B2B0BFBED32F365C96D626048D13C65962ED08445B5EE74B11203E24C0ACCD3CC13F39963632D8F4B8F8BB16B7901373C32FFD27472957A8448E414A26BB10CAE9BCFBF332BA677D59C0CCD4CCE5B34298E2B1F3250092CF602B5476922D9FA13D4AE9F54841D889FE71D67A79315A621BDAECB2FD3F1ECDAB0DC9FBDFB85AE1633038A44E15DEF1B6DDBC4AB47BB128E1C2DE8A17FD1107D8587CE96088709E17DA23DE6993973A43DFB59801A9691B7EBF5565C4FF842F5132E99288FA4CE3E6CE9333DEE052212E71EF08C5E2E385A787F1567C0CD05A4D11BF40CA19B8D49A231AA55CDE1B8C531C9FCD3B9C70AABD65372E582FCE7528B6BD8F89AA6489B1F085AE024D5A964CAEC4F3F5726CBACDB5D8429F6741FE102BC27E10724C30A64A7D3ED11F6FF41908920A1326793C7C7EDDDD2F79D8A3CE804AE53E59E43B2E0E69AF69A79D7A97A12C0A1AC7331369FCE4072879AA998CD1DC6296CB02D4B97803F1F3713F922796148E2263AFA6A72CF30C3C00297ABF2AD2D559AC4D0011A839FAAA261BB17966E80FF243B65B6209C2732F294F33936A3B8FE7C9BEBE50686BBE7F0FDCF9E24281242B10844037D9AB8A342B954B69E6456243CC13959E1B014A1389BA69B9C4E1C0869C7FE3292ED72FCF183B216F7F5EB5A7CD0A2493BCA160AE6142F4CF03110CA4782CA6C8ED558CA8AF4B14ADC4C368FF0C0CD014F7E117F56D797EF45294C8D3BCED9D5D4E3FA60592031E2925ABA72DFE5AC1D88081DB6CF68DCB256A822CE891AD12F5BB34F39CE974F7D23C0B7AB3BF12D854DA60617EB5E479A9740E00A1DCA267A3D1D212F25A06B83106CBD624CC745ACB31E0EA774F6E0D765D6134F74A3AF5B3846649C14539B7C01B484C54F71B2C5016C2EA57B16472145511130D79E23271151F370DB8A626DB218F73FF0ABFE066E2782696F6984923AA074AEA9E059AEC18F50D4E03F4B17BAD856E6C962604A02','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
]

aes_ofb_128 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','2b7e151628aed2a6abf7158809cf4f3c','3b3fd92eb72dad20333449f8e83cfb4a','000102030405060708090a0b0c0d0e0f'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','2b7e151628aed2a6abf7158809cf4f3c','7789508d16918f03f53c52dac54ed825','000102030405060708090a0b0c0d0e0f'),
	('30c81c46a35ce411e5fbc1191a0a52ef','2b7e151628aed2a6abf7158809cf4f3c','9740051e9c5fecf64344f7a82260edcc','000102030405060708090a0b0c0d0e0f'),
	('f69f2445df4f9b17ad2b417be66c3710','2b7e151628aed2a6abf7158809cf4f3c','304c6528f659c77866a510d9c1d6ae5e','000102030405060708090a0b0c0d0e0f'),
]

aes_ofb_192 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','cdc80d6fddf18cab34c25909c99a4174','000102030405060708090a0b0c0d0e0f'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','fcc28b8d4c63837c09e81700c1100401','000102030405060708090a0b0c0d0e0f'),
	('30c81c46a35ce411e5fbc1191a0a52ef','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','8d9a9aeac0f6596f559c6d4daf59a5f2','000102030405060708090a0b0c0d0e0f'),
	('f69f2445df4f9b17ad2b417be66c3710','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','6d9f200857ca6c3e9cac524bd9acc92a','000102030405060708090a0b0c0d0e0f'),
]

aes_ofb_256 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','dc7e84bfda79164b7ecd8486985d3860','000102030405060708090a0b0c0d0e0f'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','4febdc6740d20b3ac88f6ad82a4fb08d','000102030405060708090a0b0c0d0e0f'),
	('30c81c46a35ce411e5fbc1191a0a52ef','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','71ab47a086e86eedf39d1c5bba97c408','000102030405060708090a0b0c0d0e0f'),
	('f69f2445df4f9b17ad2b417be66c3710','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','0126141d67f37be8538f5a8be740e484','000102030405060708090a0b0c0d0e0f'),
]

aes_ofb_long = [
	('006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'*11,'2b7e151628aed2a6abf7158809cf4f3c','ECE71ECD7A4E3C2F643B2B0BFBED32F3B3D63D91F8B99D5EA9D0AA2D977A8675EDD972802EB60B3D8FA629EF94358D46861CF60D9F89F481632F937182C78E49D53D132260CFC3A80943E0FD169C6091FF4BBBBDEC35F4A31DDB61AFA087750D6CFCF86DAB13330125D60A2732E43A2AF3E47ABE4824C5B17DD747F267149A321ADA13409D51D4FC685ADA6789D5785FCA5EF199FD96A03879B4147C4936CC32DE864520C98DD55408CA8ED4AF1BE1F133ED53CA9FF58E6862D3E900AE66EEF75272B547BBC8919CE5503981684FEBA088F5E73BF272C820656CC9627FB4E4FC3A92A6B815CAC558B3257614AA9BB2CF2409D3633B6570EEF67A9343502D2B528078E561782917D977E6F76B13CD6526512D3D4C803BBB58E54EED5B4057EAF85DE83A7EC53FACBCA7E03EB7E027910C8DA25B75BE33B41C0C594DF6D781E821193963C9F658D380A460561B2F0C9C3D7639A4E4EE2DA87653DA86FAD6D5280857CEC28CC40D082C81C672D9B36CD169A6803ACA4C8DAAD77953B296FBAF480FA146F8B41DCBD487A368851A207C90228DBF7BAEEB38F23F98520E52145D809DB530D3E690C2A91B8367B815C4FFC0AE7171582169D6A7FD073A1F9DE1182FC98D1D5B3E39B44E054218B80091333D5B751C0530BADF4361C5A95CB26634AE788F7B6D2CCA543FDE48172A24E4D991F9262CFB8ED09FFE4E1506DA6478EF879847F8CE44569A9AC66E124CEE5944D2DC87742CA1B598B3C7D54662F8A5783A0C6689C949C54E148C2C88DFBA4F10F0234BA62E4DDEA30F5AD3D209829CCB73C22141D56050FB75E0E7D1B822F6FFC6AB92E8DB12A5C6B62064B692F8B118CC38F0436433B5370CE5A79D09A7081703EEA59F64B7361AA50476DD2F7074CA37C51935DCBC78A806F92C1186033070D5C3FABACAAE39CB7FBA0654D13413E94F6E9FDDB7D2D4EC1985CCF2E2011C186BD0C16AA95A0C7FDDF1B36490780EB646EEB7B0B377E970FD7D2E9A06','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
]

aes_ctr_128 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','2b7e151628aed2a6abf7158809cf4f3c','874d6191b620e3261bef6864990db6ce','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','2b7e151628aed2a6abf7158809cf4f3c','9806f66b7970fdff8617187bb9fffdff','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
	('30c81c46a35ce411e5fbc1191a0a52ef','2b7e151628aed2a6abf7158809cf4f3c','5ae4df3edbd5d35e5b4f09020db03eab','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
	('f69f2445df4f9b17ad2b417be66c3710','2b7e151628aed2a6abf7158809cf4f3c','1e031dda2fbe03d1792170a0f3009cee','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
]

aes_ctr_192 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','1abc932417521ca24f2b0459fe7e6e0b','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','090339ec0aa6faefd5ccc2c6f4ce8e94','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
	('30c81c46a35ce411e5fbc1191a0a52ef','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','1e36b26bd1ebc670d1bd1d665620abf7','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
	('f69f2445df4f9b17ad2b417be66c3710','8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','4f78a7f6d29809585a97daec58c6b050','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
]

aes_ctr_256 = [
	# plaintext, key, ciphertext, iv
	('6bc1bee22e409f96e93d7e117393172a','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','601ec313775789a5b7a7f504bbf3d228','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
	('ae2d8a571e03ac9c9eb76fac45af8e51','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','f443e3ca4d62b59aca84e990cacaf5c5','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
	('30c81c46a35ce411e5fbc1191a0a52ef','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','2b0930daa23de94ce87017ba2d84988d','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
	('f69f2445df4f9b17ad2b417be66c3710','603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','dfc9c58db67aada613c2dd08457941a6','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
]

aes_ctr_long = [
	('006bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'*11,'2b7e151628aed2a6abf7158809cf4f3c','ECE71ECD7A4E3C2F643B2B0BFBED32F31C8551B6306D52CF843EC0B85015DC203B1C0B643E2A6BABAF5133DA0EA06616076AA6BBB52ED75DC3A71A9A6E8AC7C9A00D2C39AA68BF4E6FFED9AAEE5AD6914FB3EA77C7B61FF6BF564F2F1225ACB4B5889CB1559888A5817849C382E168482F75381F63868C468E4D1583B1FE71DD808CB94D8150AAB9D530A0FC17CDE748E95545D8A033B2F61F1954D0C0226168022E1CD7E031C57D048AC560F152960F47705E174D956D4BB53AE80BFFCD1BD569ED8EFFA223C00558B702405F33E6E0EDB2D9B0C148A1441CC80D6ABBCE785AA1B9DAB7CB8832F1B12D2EE60EE2DFCA37942CA1724E5602B7B70525AC9662028A22DB234676615DB474538CBC8D197F38C88BCC4F9E8D207538CA18DE5F095420A2E4D5868CEBB8B34A9377DC52D119790B65210F1B346F5E00D9BD00A8847048913D80726B9B745D565E6284B986DBAEA997FFC5A0DE5051527D44B2C1266DBC9130A6EB15F37A0F00B6286D6678CA651C07743BD37F2E8F6A94F5ED8C63428AE4883A9695183807E104BC335C64FEAAC40A605913DF98FF44E0801B31A968CCE5DCAFADE1E017FA711E05FF5A54BFA1999C2C463F97A3A66B30211BD306C8911C98F8EE5EF47A54746A4D16B7C7424A6954B4FC3BCF1A41BDE8A19CE1027AE86A320D0E5E7D3C7E50CFD0C4665B811D86C313F09ADE5B4DBE017231859881E5873E9EDB2011CF5920D2F7277C4DE1AC430A1849F0B870A69ABE701B6D0B5123E5FF53395409177CF84BF41EC33C5E4BCC2CF29258DC7C260471AABDA49FDE62915758EE4E578D0F7698E6456BC144573739D5D508CC76B389359D2A0ECB5B7EE5FCB4C3151D5AF7C71819EA3DD5F36C7B27E551FD2373D07FFDC76A13FC4B10A6F29A83D6F465ACB6960671EACF21A3E1CB4411C4DAA0C2A87DAED28AEE60B7EC0258A9AF125F2DDC80B9877EFE0F372D9B832C786770A84EA1A07CB6E1A9907D651BBD0EFDEF2AFFC3','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
]

aes_ccm = [
	#plain, key, cipher, nonce, adata, asize
	('08090A0B0C0D0E0F101112131415161718191A1B1C1D1E', 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF', '588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0', '00000003020100A0A1A2A3A4A5', '0001020304050607', 8),
	('08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF', '72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3BA091D56E10400916', '00000004030201A0A1A2A3A4A5', '0001020304050607', 8),
	#???('08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20', 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF', '51B1E5F44A197D1DA46B0F8E2D282AE871E838BB64DA8596574ADAA76FBD9FB0C5', '00000003020100A0A1A2A3A4A5', '0001020304050607', 8),
	('0C0D0E0F101112131415161718191A1B1C1D1E', 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF', 'A28C6865939A9A79FAAA5C4C2A9D4A91CDAC8C96C861B9C9E61EF1', '00000006050403A0A1A2A3A4A5', '000102030405060708090A0B', 8),
	('0C0D0E0F101112131415161718191A1B1C1D1E1F', 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF', 'DCF1FB7B5D9E23FB9D4E131253658AD86EBDCA3E51E83F077D9C2D93', '00000007060504A0A1A2A3A4A5', '000102030405060708090A0B', 8),
	('0C0D0E0F101112131415161718191A1B1C1D1E1F20', 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF', '6FC1B011F006568B5171A42D953D469B2570A4BD87405A0443AC91CB94', '00000008070605A0A1A2A3A4A5', '000102030405060708090A0B', 8),
	('08090A0B0C0D0E0F101112131415161718191A1B1C1D1E', 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF', '0135D1B2C95F41D5D1D4FEC185D166B8094E999DFED96C048C56602C97ACBB7490', '00000009080706A0A1A2A3A4A5', '0001020304050607', 10),
	('08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF', '7B75399AC0831DD2F0BBD75879A2FD8F6CAE6B6CD9B7DB24C17B4433F434963F34B4', '0000000A090807A0A1A2A3A4A5', '0001020304050607', 10),
	('08E8CF97D820EA258460E96AD9CF5289054D895CEAC47C', 'D7828D13B2B0BDC325A76236DF93CC6B', '4CB97F86A2A4689A877947AB8091EF5386A6FFBDD080F8E78CF7CB0CDDD7B3', '00412B4EA9CDBE3C9696766CFA', '0BE1A88BACE018B1', 8),
	('ABF21C0B02FEB88F856DF4A37381BCE3CC128517D4', 'D7828D13B2B0BDC325A76236DF93CC6B', 'F32905B88A641B04B9C9FFB58CC390900F3DA12AB16DCE9E82EFA16DA62059', '008D493B30AE8B3C9696766CFA', '6E37A6EF546D955D34AB6059', 10),
]

aes_gcm_128 = [
	('00000000000000000000000000000000','000000000000000000000000','','','','58e2fccefa7e3061367f1d57a4e7455a'),
	('00000000000000000000000000000000','000000000000000000000000','00000000000000000000000000000000','0388dace60b6a392f328c2b971b2fe78','','ab6e47d42cec13bdf53a67b21257bddf'),
	('feffe9928665731c6d6a8f9467308308','cafebabefacedbaddecaf888','d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255','42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985','','4d5c2af327cd64a62cf35abd2ba6fab4'),
	('feffe9928665731c6d6a8f9467308308','cafebabefacedbaddecaf888','d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39','42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091','feedfacedeadbeeffeedfacedeadbeefabaddad2','5bc94fbc3221a5db94fae95ae7121a47'),
	('feffe9928665731c6d6a8f9467308308','cafebabefacedbad','d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39','61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598','feedfacedeadbeeffeedfacedeadbeefabaddad2','3612d2e79e3b0785561be14aaca2fccb'),
	('feffe9928665731c6d6a8f9467308308','9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b','d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39','8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5','feedfacedeadbeeffeedfacedeadbeefabaddad2','619cc5aefffe0bfa462af43c1699d050'),
	('00000000000000000000000000000000','000000000000000000000000','','','d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad','5fea793a2d6f974d37e68e0cb8ff9492'),
	('00000000000000000000000000000000','000000000000000000000000','000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000','0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0200211214e7394da2089b6acd093abe0','','9dd0a376b08e40eb00c35f29f9ea61a4'),
	('00000000000000000000000000000000','000000000000000000000000','0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000','0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0200211214e7394da2089b6acd093abe0c94da219118e297d7b7ebcbcc9c388f28ade7d85a8ee35616f7124a9d5270291','','98885a3a22bd4742fe7b72172193b163'),
	('00000000000000000000000000000000','000000000000000000000000','0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000','0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0200211214e7394da2089b6acd093abe0c94da219118e297d7b7ebcbcc9c388f28ade7d85a8ee35616f7124a9d527029195b84d1b96c690ff2f2de30bf2ec89e00253786e126504f0dab90c48a30321de3345e6b0461e7c9e6c6b7afedde83f40','','cac45f60e31efd3b5a43b98a22ce1aa1'),
	('00000000000000000000000000000000','ffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000','000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000','56b3373ca9ef6e4a2b64fe1e9a17b61425f10d47a75a5fce13efc6bc784af24f4141bdd48cf7c770887afd573cca5418a9aeffcd7c5ceddfc6a78397b9a85b499da558257267caab2ad0b23ca476a53cb17fb41c4b8b475cb4f3f7165094c229c9e8c4dc0a2a5ff1903e501511221376a1cdb8364c5061a20cae74bc4acd76ceb0abc9fd3217ef9f8c90be402ddf6d8697f4f880dff15bfb7a6b28241ec8fe183c2d59e3f9dfff653c7126f0acb9e64211f42bae12af462b1070bef1ab5e3606','','566f8ef683078bfdeeffa869d751a017'),
	('843ffcf5d2b72694d19ed01d01249412','dbcca32ebf9b804617c3aa9e','000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f','6268c6fa2a80b2d137467f092f657ac04d89be2beaa623d61b5a868c8f03ff95d3dcee23ad2f1ab3a6c80eaf4b140eb05de3457f0fbc111a6b43d0763aa422a3013cf1dc37fe417d1fbfc449b75d4cc5','00000000000000000000000000000000101112131415161718191a1b1c1d1e1f','3b629ccfbc1119b7319e1dce2cd6fd6d'),
]

aes_gcm_256 = [
	('0000000000000000000000000000000000000000000000000000000000000000','000000000000000000000000','','','','530f8afbc74536b9a963b4f1c4cb738b'),
	('0000000000000000000000000000000000000000000000000000000000000000','000000000000000000000000','00000000000000000000000000000000','cea7403d4d606b6e074ec5d3baf39d18','','d0d1c8a799996bf0265b98b5d48ab919'),
	('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308','cafebabefacedbaddecaf888','d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255','522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad','','b094dac5d93471bdec1a502270e3cc6c'),
	('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308','cafebabefacedbaddecaf888','d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39','522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662','feedfacedeadbeeffeedfacedeadbeefabaddad2','76fc6ece0f4e1768cddf8853bb2d551b'),
	('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308','cafebabefacedbad','d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39','c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f','feedfacedeadbeeffeedfacedeadbeefabaddad2','3a337dbf46a792c45e454913fe2ea8f2'),
	('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308','9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b','d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39','5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f','feedfacedeadbeeffeedfacedeadbeefabaddad2','a44a8266ee1c8eb0c8b5d4cf5ae9f19a'),
]


def cfb_enc(cipherobj:symmetric.symmetricBASE, vector, segment_size = 8):
	data_total = b''
	enc_data_total = b''
	ctx = None
	key = None
	for i, res in enumerate(vector):
		plaintext, key, ciphertext, iv = res
		plaintext = bytes.fromhex(plaintext)
		key = bytes.fromhex(key)
		ciphertext = bytes.fromhex(ciphertext)
		iv = bytes.fromhex(iv)
		if i == 0:
			ctx = cipherobj(key, symmetric.MODE_CFB, iv, segment_size = segment_size)
		data_total += plaintext
		enc_data = ctx.encrypt(plaintext)
		enc_data_total += enc_data
		if enc_data != ciphertext:
			raise Exception('Ciphertext doesnt match to vector! CFB %s Cipher: \r\n%s \r\nVector: \r\n%s' % (i, enc_data.hex(), ciphertext.hex()))
		
	ctx = cipherobj(key, symmetric.MODE_CFB, iv, segment_size = segment_size)
	dec_data = ctx.decrypt(enc_data_total)
	if dec_data != data_total:
		raise Exception('Decrypted data doesnt match plaintext! CFB Cipher: \r\n%s \r\nPlaintext: \r\n%s' % (dec_data.hex(), plaintext.hex()))
	
	return True
	
def cfb_8_enc(cipherobj:symmetric.symmetricBASE, vector, segment_size = 8):
	ctx = None
	for i, res in enumerate(vector):
		plaintext, key, ciphertext, iv = res
		plaintext = bytes.fromhex(plaintext)
		key = bytes.fromhex(key)
		ciphertext = bytes.fromhex(ciphertext)
		iv = bytes.fromhex(iv)
		ctx = cipherobj(key, symmetric.MODE_CFB, iv, segment_size = segment_size)
		enc_data = ctx.encrypt(plaintext)
		if enc_data != ciphertext:
			raise Exception('Ciphertext doesnt match to vector! CFB %s Cipher: \r\n%s \r\nVector: \r\n%s' % (i, enc_data.hex(), ciphertext.hex()))
	return True
	
def ctr_enc(cipherobj:symmetric.symmetricBASE, vector):
	data_total = b''
	enc_data_total = b''
	ctx = None
	key = None
	for i, res in enumerate(vector):
		plaintext, key, ciphertext, iv = res
		plaintext = bytes.fromhex(plaintext.replace(' ', ''))
		key = bytes.fromhex(key.replace(' ', ''))
		ciphertext = bytes.fromhex(ciphertext.replace(' ', ''))
		iv = bytes.fromhex(iv.replace(' ', ''))
		if i == 0:
			ctx = cipherobj(key, symmetric.MODE_CTR, iv)
		data_total += plaintext
		enc_data = ctx.encrypt(plaintext)
		enc_data_total += enc_data
		if enc_data != ciphertext:
			raise Exception('Ciphertext doesnt match to vector! CTR %s Cipher: \r\n%s \r\nVector: \r\n%s' % (i, enc_data.hex(), ciphertext.hex()))
	
	ctx = cipherobj(key, symmetric.MODE_CTR, iv)
	dec_data = ctx.decrypt(enc_data_total)
	if dec_data != data_total:
		raise Exception('Decrypted data doesnt match plaintext! OFB Cipher: \r\n%s \r\nPlaintext: \r\n%s' % (dec_data.hex(), plaintext.hex()))
	return True
	
def ofb_enc(cipherobj, vector):
	data_total = b''
	enc_data_total = b''
	ctx = None
	key = None
	for i, res in enumerate(vector):
		plaintext, key, ciphertext, iv = res
		plaintext = bytes.fromhex(plaintext)
		key = bytes.fromhex(key)
		ciphertext = bytes.fromhex(ciphertext)
		iv = bytes.fromhex(iv)
		if i == 0:
			ctx = cipherobj(key, symmetric.MODE_OFB, iv)
		data_total += plaintext
		enc_data = ctx.encrypt(plaintext)
		enc_data_total += enc_data
		if enc_data != ciphertext:
			raise Exception('Ciphertext doesnt match to vector! OFB %s Cipher: \r\n%s \r\nVector: \r\n%s' % (i, enc_data.hex(), ciphertext.hex()))
	
	ctx = cipherobj(key, symmetric.MODE_OFB, iv)
	dec_data = ctx.decrypt(enc_data_total)
	if dec_data != data_total:
		raise Exception('Decrypted data doesnt match plaintext! OFB Cipher: \r\n%s \r\nPlaintext: \r\n%s' % (dec_data.hex(), plaintext.hex()))
	
	return True

def cbc_enc(cipherobj, vector):
	data_total = b''
	enc_data_total = b''
	ctx = None
	key = None
	for i, res in enumerate(vector):
		plaintext, key, ciphertext, iv = res
		plaintext = bytes.fromhex(plaintext)
		key = bytes.fromhex(key)
		ciphertext = bytes.fromhex(ciphertext)
		iv = bytes.fromhex(iv)
		if i == 0:
			ctx = cipherobj(key, symmetric.MODE_CBC, iv)
		data_total += plaintext
		enc_data = ctx.encrypt(plaintext)
		enc_data_total += enc_data
		if enc_data != ciphertext:
			raise Exception('Ciphertext doesnt match to vector! CBC %s Cipher: \r\n%s \r\nVector: \r\n%s' % (i, enc_data.hex(), ciphertext.hex()))
	
	ctx = cipherobj(key, symmetric.MODE_CBC, iv)
	dec_data = ctx.decrypt(enc_data_total)
	if dec_data != data_total:
		raise Exception('Decrypted data doesnt match plaintext! CBC Cipher: \r\n%s \r\nPlaintext: \r\n%s' % (dec_data.hex(), plaintext.hex()))
	return True
	
def ccm_enc(cipherobj, vector):
	for i, res in enumerate(vector):
		plaintext, key, ciphertext, nonce,adata, asize = res
		plaintext = bytes.fromhex(plaintext)
		key = bytes.fromhex(key)
		ciphertext = bytes.fromhex(ciphertext)
		nonce = bytes.fromhex(nonce)
		adata = bytes.fromhex(adata)
		ctx = cipherobj(key, symmetric.MODE_CCM, nonce, segment_size=asize)
		enc_data, mac = ctx.encrypt(plaintext, adata)
		if (enc_data+mac) != ciphertext:
			raise Exception('Ciphertext doesnt match to vector! CCM %s Cipher: %s Vector: %s' % (i, enc_data, ciphertext))
		ctx = cipherobj(key, symmetric.MODE_CCM, nonce, segment_size=asize)
		dec_data = ctx.decrypt(enc_data, adata, mac)
		if dec_data != plaintext:
			raise Exception('Decrypted data doesnt match plaintext! CCM %s Cipher: \r\n%s \r\nPlaintext: \r\n%s' % (i, dec_data.hex(), plaintext.hex()))
	return True

def gcm_enc(cipherobj, vector, skip = 0):
	for i, res in enumerate(vector[skip:]):
		key, nonce, plaintext, ciphertext, adata, mac = res
		plaintext = bytes.fromhex(plaintext)
		key = bytes.fromhex(key)
		ciphertext = bytes.fromhex(ciphertext)
		nonce = bytes.fromhex(nonce)
		adata = bytes.fromhex(adata)
		mac = bytes.fromhex(mac)
		ctx = cipherobj(key, symmetric.MODE_GCM, nonce, segment_size=len(mac)) # size= 16
		enc_data, mac_res = ctx.encrypt(plaintext, adata)
		if (enc_data+mac_res) != (ciphertext + mac):
			raise Exception('Ciphertext doesnt match to vector! GCM %s Cipher: %s Vector: %s' % (i, enc_data+mac_res, ciphertext + mac))
		ctx = cipherobj(key, symmetric.MODE_GCM, nonce, segment_size=len(mac))
		dec_data = ctx.decrypt(enc_data, adata, mac_res)
		if dec_data != plaintext:
			raise Exception('Decrypted data doesnt match plaintext! GCM %s Cipher: \r\n%s \r\nPlaintext: \r\n%s' % (i, dec_data.hex(), plaintext.hex()))
	return True

	
def ecb_enc(cipherobj, vector):
	for i, res in enumerate(vector):
		plaintext, key, ciphertext = res
		plaintext = bytes.fromhex(plaintext)
		key = bytes.fromhex(key)
		ciphertext = bytes.fromhex(ciphertext)
		ctx = cipherobj(key, symmetric.MODE_ECB)
		if len(key) != len(plaintext):
			enc_data = b''
			n = len(key)
			for chunk in [plaintext[i:i+n] for i in range(0, len(plaintext), n)]:
				enc_data += ctx.encrypt(chunk)
		else:
			enc_data = ctx.encrypt(plaintext)
		if enc_data != ciphertext:
			raise Exception('Ciphertext doesnt match to vector! ECB %s Cipher: %s Vector: %s' % (i, enc_data, ciphertext))
	return True

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ecb_128(cipherobj):
	ecb_enc(cipherobj, aes_128_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ecb_192(cipherobj):
	ecb_enc(cipherobj, aes_192_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ecb_256(cipherobj):
	ecb_enc(cipherobj, aes_256_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ecb_long(cipherobj):
	ecb_enc(cipherobj, aes_ecb_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_cbc_128(cipherobj):
	cbc_enc(cipherobj, aes_cbc_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_cbc_192(cipherobj):
	cbc_enc(cipherobj, aes_cbc_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_cbc_256(cipherobj):
	cbc_enc(cipherobj, aes_cbc_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_cbc_long(cipherobj):
	cbc_enc(cipherobj, aes_cbc_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_cfb_fb1(cipherobj):
	cfb_8_enc(cipherobj, aes_cfb_feedbacksize_1, 8)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_cfb_128_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_128_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_cfb_192_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_192_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_cfb_256_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_256_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_cfb_long_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_long, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ofb_128(cipherobj):
	ofb_enc(cipherobj, aes_ofb_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ofb_192(cipherobj):
	ofb_enc(cipherobj, aes_ofb_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ofb_256(cipherobj):
	ofb_enc(cipherobj, aes_ofb_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ofb_long(cipherobj):
	ofb_enc(cipherobj, aes_ofb_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ctr_128(cipherobj):
	ctr_enc(cipherobj, aes_ctr_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ctr_192(cipherobj):
	ctr_enc(cipherobj, aes_ctr_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ctr_256(cipherobj):
	ctr_enc(cipherobj, aes_ctr_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ctr_long(cipherobj):
	ctr_enc(cipherobj, aes_ctr_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_ccm(cipherobj):
	ccm_enc(cipherobj, aes_ccm)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_gcm_128(cipherobj):
	gcm_enc(cipherobj, aes_gcm_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodome')])
def test_gcm_256(cipherobj):
	gcm_enc(cipherobj, aes_gcm_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ecb_128(cipherobj):
	ecb_enc(cipherobj, aes_128_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ecb_192(cipherobj):
	ecb_enc(cipherobj, aes_192_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ecb_256(cipherobj):
	ecb_enc(cipherobj, aes_256_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ecb_long(cipherobj):
	ecb_enc(cipherobj, aes_ecb_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_cbc_128(cipherobj):
	cbc_enc(cipherobj, aes_cbc_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_cbc_192(cipherobj):
	cbc_enc(cipherobj, aes_cbc_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_cbc_256(cipherobj):
	cbc_enc(cipherobj, aes_cbc_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_cbc_long(cipherobj):
	cbc_enc(cipherobj, aes_cbc_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_cfb_fb1(cipherobj):
	cfb_8_enc(cipherobj, aes_cfb_feedbacksize_1, 8)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_cfb_128_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_128_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_cfb_192_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_192_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_cfb_256_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_256_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_cfb_long_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_long, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ofb_128(cipherobj):
	ofb_enc(cipherobj, aes_ofb_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ofb_192(cipherobj):
	ofb_enc(cipherobj, aes_ofb_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ofb_256(cipherobj):
	ofb_enc(cipherobj, aes_ofb_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ofb_long(cipherobj):
	ofb_enc(cipherobj, aes_ofb_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ctr_128(cipherobj):
	ctr_enc(cipherobj, aes_ctr_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ctr_192(cipherobj):
	ctr_enc(cipherobj, aes_ctr_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ctr_256(cipherobj):
	ctr_enc(cipherobj, aes_ctr_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ctr_long(cipherobj):
	ctr_enc(cipherobj, aes_ctr_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_ccm(cipherobj):
	ccm_enc(cipherobj, aes_ccm)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_gcm_128(cipherobj):
	gcm_enc(cipherobj, aes_gcm_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pycryptodomex')])
def test_gcm_256(cipherobj):
	gcm_enc(cipherobj, aes_gcm_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ecb_128(cipherobj):
	ecb_enc(cipherobj, aes_128_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ecb_192(cipherobj):
	ecb_enc(cipherobj, aes_192_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ecb_256(cipherobj):
	ecb_enc(cipherobj, aes_256_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ecb_long(cipherobj):
	ecb_enc(cipherobj, aes_ecb_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_cbc_128(cipherobj):
	cbc_enc(cipherobj, aes_cbc_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_cbc_192(cipherobj):
	cbc_enc(cipherobj, aes_cbc_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_cbc_256(cipherobj):
	cbc_enc(cipherobj, aes_cbc_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_cbc_long(cipherobj):
	cbc_enc(cipherobj, aes_cbc_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_cfb_fb1(cipherobj):
	cfb_8_enc(cipherobj, aes_cfb_feedbacksize_1, 8)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_cfb_128_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_128_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_cfb_192_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_192_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_cfb_256_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_256_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_cfb_long_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_long, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ofb_128(cipherobj):
	ofb_enc(cipherobj, aes_ofb_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ofb_192(cipherobj):
	ofb_enc(cipherobj, aes_ofb_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ofb_256(cipherobj):
	ofb_enc(cipherobj, aes_ofb_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ofb_long(cipherobj):
	ofb_enc(cipherobj, aes_ofb_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ctr_128(cipherobj):
	ctr_enc(cipherobj, aes_ctr_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ctr_192(cipherobj):
	ctr_enc(cipherobj, aes_ctr_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ctr_256(cipherobj):
	ctr_enc(cipherobj, aes_ctr_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ctr_long(cipherobj):
	ctr_enc(cipherobj, aes_ctr_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_ccm(cipherobj):
	ccm_enc(cipherobj, aes_ccm)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_gcm_128(cipherobj):
	gcm_enc(cipherobj, aes_gcm_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'cryptography')])
def test_gcm_256(cipherobj):
	gcm_enc(cipherobj, aes_gcm_256)

#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ecb_128(cipherobj):
#	ecb_enc(cipherobj, aes_128_ecb)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ecb_192(cipherobj):
#	ecb_enc(cipherobj, aes_192_ecb)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ecb_256(cipherobj):
#	ecb_enc(cipherobj, aes_256_ecb)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ecb_long(cipherobj):
#	ecb_enc(cipherobj, aes_ecb_long)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_cbc_128(cipherobj):
#	cbc_enc(cipherobj, aes_cbc_128)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_cbc_192(cipherobj):
#	cbc_enc(cipherobj, aes_cbc_192)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_cbc_256(cipherobj):
#	cbc_enc(cipherobj, aes_cbc_256)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_cbc_long(cipherobj):
#	cbc_enc(cipherobj, aes_cbc_long)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_cfb_fb1(cipherobj):
#	cfb_8_enc(cipherobj, aes_cfb_feedbacksize_1, 8)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_cfb_128_fb16(cipherobj):
#	cfb_enc(cipherobj, aes_cfb_128_feedbacksize_16, 128)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_cfb_192_fb16(cipherobj):
#	cfb_enc(cipherobj, aes_cfb_192_feedbacksize_16, 128)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_cfb_256_fb16(cipherobj):
#	cfb_enc(cipherobj, aes_cfb_256_feedbacksize_16, 128)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_cfb_long_fb16(cipherobj):
#	cfb_enc(cipherobj, aes_cfb_long, 128)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ofb_128(cipherobj):
#	ofb_enc(cipherobj, aes_ofb_128)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ofb_192(cipherobj):
#	ofb_enc(cipherobj, aes_ofb_192)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ofb_256(cipherobj):
#	ofb_enc(cipherobj, aes_ofb_256)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ofb_long(cipherobj):
#	ofb_enc(cipherobj, aes_ofb_long)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ctr_128(cipherobj):
#	ctr_enc(cipherobj, aes_ctr_128)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ctr_192(cipherobj):
#	ctr_enc(cipherobj, aes_ctr_192)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ctr_256(cipherobj):
#	ctr_enc(cipherobj, aes_ctr_256)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ctr_long(cipherobj):
#	ctr_enc(cipherobj, aes_ctr_long)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_ccm(cipherobj):
#	ccm_enc(cipherobj, aes_ccm)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_gcm_128(cipherobj):
#	gcm_enc(cipherobj, aes_gcm_128)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'crypto')])
#def test_gcm_256(cipherobj):
#	gcm_enc(cipherobj, aes_gcm_256)
#
#
@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ecb_128(cipherobj):
	ecb_enc(cipherobj, aes_128_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ecb_192(cipherobj):
	ecb_enc(cipherobj, aes_192_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ecb_256(cipherobj):
	ecb_enc(cipherobj, aes_256_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ecb_long(cipherobj):
	ecb_enc(cipherobj, aes_ecb_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_cbc_128(cipherobj):
	cbc_enc(cipherobj, aes_cbc_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_cbc_192(cipherobj):
	cbc_enc(cipherobj, aes_cbc_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_cbc_256(cipherobj):
	cbc_enc(cipherobj, aes_cbc_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_cbc_long(cipherobj):
	cbc_enc(cipherobj, aes_cbc_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_cfb_fb1(cipherobj):
	cfb_8_enc(cipherobj, aes_cfb_feedbacksize_1, 8)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_cfb_128_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_128_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_cfb_192_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_192_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_cfb_256_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_256_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_cfb_long_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_long, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ofb_128(cipherobj):
	ofb_enc(cipherobj, aes_ofb_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ofb_192(cipherobj):
	ofb_enc(cipherobj, aes_ofb_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ofb_256(cipherobj):
	ofb_enc(cipherobj, aes_ofb_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ofb_long(cipherobj):
	ofb_enc(cipherobj, aes_ofb_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ctr_128(cipherobj):
	ctr_enc(cipherobj, aes_ctr_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ctr_192(cipherobj):
	ctr_enc(cipherobj, aes_ctr_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ctr_256(cipherobj):
	ctr_enc(cipherobj, aes_ctr_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ctr_long(cipherobj):
	ctr_enc(cipherobj, aes_ctr_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_ccm(cipherobj):
	ccm_enc(cipherobj, aes_ccm)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_gcm_128(cipherobj):
	gcm_enc(cipherobj, aes_gcm_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'pure')])
def test_gcm_256(cipherobj):
	gcm_enc(cipherobj, aes_gcm_256)


@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ecb_128(cipherobj):
	ecb_enc(cipherobj, aes_128_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ecb_192(cipherobj):
	ecb_enc(cipherobj, aes_192_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ecb_256(cipherobj):
	ecb_enc(cipherobj, aes_256_ecb)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ecb_long(cipherobj):
	ecb_enc(cipherobj, aes_ecb_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_cbc_128(cipherobj):
	cbc_enc(cipherobj, aes_cbc_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_cbc_192(cipherobj):
	cbc_enc(cipherobj, aes_cbc_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_cbc_256(cipherobj):
	cbc_enc(cipherobj, aes_cbc_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_cbc_long(cipherobj):
	cbc_enc(cipherobj, aes_cbc_long)

#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
#def test_cfb_fb1(cipherobj):
#	cfb_8_enc(cipherobj, aes_cfb_feedbacksize_1, 8)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_cfb_128_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_128_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_cfb_192_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_192_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_cfb_256_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_256_feedbacksize_16, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_cfb_long_fb16(cipherobj):
	cfb_enc(cipherobj, aes_cfb_long, 128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ofb_128(cipherobj):
	ofb_enc(cipherobj, aes_ofb_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ofb_192(cipherobj):
	ofb_enc(cipherobj, aes_ofb_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ofb_256(cipherobj):
	ofb_enc(cipherobj, aes_ofb_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ofb_long(cipherobj):
	ofb_enc(cipherobj, aes_ofb_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ctr_128(cipherobj):
	ctr_enc(cipherobj, aes_ctr_128)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ctr_192(cipherobj):
	ctr_enc(cipherobj, aes_ctr_192)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ctr_256(cipherobj):
	ctr_enc(cipherobj, aes_ctr_256)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ctr_long(cipherobj):
	ctr_enc(cipherobj, aes_ctr_long)

@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
def test_ccm(cipherobj):
	ccm_enc(cipherobj, aes_ccm)

#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
#def test_gcm_128(cipherobj):
#	gcm_enc(cipherobj, aes_gcm_128)
#
#@pytest.mark.parametrize("cipherobj", [get_cipher_by_name('AES', 'mbedtls')])
#def test_gcm_256(cipherobj):
#	gcm_enc(cipherobj, aes_gcm_256)

