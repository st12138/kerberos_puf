from gmssl.func import xor, list_to_bytes, bytes_to_list, padding
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import base64
class sm4kerberos:
    def __init__(self):
        self.key=b''
        self.value=b''
        self.iv=b''
        self.sm4=CryptSM4()

    def encrypt(self,key,massage):
        self.value=massage.encode('utf-8')
        self.key=key.encode('utf-8')
        self.sm4.set_key(self.key,SM4_ENCRYPT)
        encrypt_value=self.sm4.crypt_ecb(self.value)
        encrypt_values=base64.b64encode(encrypt_value)
        return encrypt_values

    def decrypt(self,key,demassage):
        self.value=base64.b64decode(demassage)
        self.key=key.encode('utf-8')
        self.sm4.set_key(self.key,SM4_DECRYPT)
        decrypt_value=self.sm4.crypt_ecb(self.value)
        return decrypt_value

