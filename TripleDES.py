# coding:gbk
'''
Author:       ����Joker
Purpose:    ����DES�ӽ���
Date:          2020��1��7��
Arguments:
Outputs:
Dependencies:

History:
--------------------------------------------------------------
Date:
Author:
Modification:
--------------------------------------------------------------
'''
from Crypto.Cipher import DES3
import base64


class prpcrypt():
    def __init__(self):
        self.mode = DES3.MODE_ECB 
        # ����ģʽ
        self.BS = DES3.block_size

    def pad(self, s):
        bw = self.BS - len(s) % self.BS
        if bw != 8:
            # ÿ8λһ�飬����8λ��Ҫ��λ��
            lackLength = self.BS - len(s) % self.BS
            midStr = (self.BS - len(s) % self.BS) * chr(32)
            return s + midStr.encode('UTF-8')
            # ���� ��λ���bytes��
        else:
            return s
            # ֱ�ӷ���

    def unpad(self, s):
        bw = self.BS - len(s) % self.BS
        if bw !=8:
            return s[0:-ord(s[-1])]
        return s

    def encrypt(self, text, key):
        # ����
        text = self.pad(text)

        cryptor = DES3.new(key, self.mode)
        x = len(text) % 8
        if x != 0:
            text = text + '\0' * (8 - x)

        self.ciphertext = cryptor.encrypt(text)
        return base64.standard_b64encode(self.ciphertext).decode("utf-8")

    def decrypt(self, text, key):
        # ����
        cryptor = DES3.new(key, self.mode)
        de_text = base64.standard_b64decode(text)
        plain_text = cryptor.decrypt(de_text)
        st = str(plain_text.decode("utf-8")).rstrip('\0')
        out = self.unpad(st)
        return out


# �����������������շ�װ�ù��в�ģ����õ�TDES�ӽ��ܷ���

def TDES_Encrypt(prpcrypt, TDES_DecryptText, TDES_Key):
    # ���ܣ�����һ��TDES����str�͵����ĺ�24λstr����Կ

    TDES_DecryptText = TDES_DecryptText.encode('UTF-8')
    TDES_Key = TDES_Key.encode('UTF-8')
    TDES_EncryptText = prpcrypt.encrypt(TDES_DecryptText, TDES_Key)
    print('����TDES����Ϊ��', TDES_EncryptText)

    return TDES_EncryptText
    # ����TDES���ܵ�str����


def TDES_Decrypt(prpcypt, TDES_EncryptText, TDES_Key):
    # ���ܣ�����һ��TDES����str�͵����ĺ�24λstr����Կ

    print('TDES����Ϊ��', TDES_EncryptText)
    TDES_EncryptText = TDES_EncryptText.encode('UTF-8')
    TDES_Key = TDES_Key.encode('UTF-8')
    TDES_DecryptText = prpcypt.decrypt(TDES_EncryptText, TDES_Key)
    print('���ܵõ�TDES����Ϊ��', TDES_DecryptText)
    print()

    return TDES_DecryptText.strip(chr(32))
    # ȥ�����Ŀո�󷵻�str���͵�����


# example
"""
test = prpcrypt()
encryText = TDES_Encrypt(test, 'TDES_test_text', '1234567887654321keykey00')
decryText = TDES_Decrypt(test, encryText, '1234567887654321keykey00')
print(encryText)
print(decryText)

����TDES����Ϊ�� N+MkEssaC0s=
���ܵõ�TDES����Ϊ�� wumin   

N+MkEssaC0s=
wumin
"""
