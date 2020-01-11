# coding:gbk
'''
Author:       ����Joker
Purpose:    ԭʼRSA���������в�ģ���ṩǩ������ǩ�����ܺͽ���
Date:          2020��1��6��
Arguments:
Outputs:    rsa_sign(data, privatePemPath)
            rsa_verify(signature, data, publicPemPath)
            rsa_encrypt(publicPemPath, RSA_DecryptText)
            rsa_decrypt(privatePemPath, RSA_EncrptText)
Dependencies:

History:
--------------------------------------------------------------
Date:
Author:
Modification:
--------------------------------------------------------------
'''
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as SV_PKCS1_v1_5
from Crypto.Cipher import PKCS1_v1_5 as ED_PKCS1_v1_5
# ����SV��ED������cipher�಻ͬ������
from Crypto.Hash import MD5
import base64


def rsa_sign(data, privatePemPath):
    # ���Լ�˽Կ��str��data��MD5ֵ����ǩ��

    private_key_file = open(privatePemPath, 'r')
    pri_key = RSA.importKey(private_key_file.read())
    signer = SV_PKCS1_v1_5.new(pri_key)
    hash_obj = my_hash(data)
    signature = base64.b64encode(signer.sign(hash_obj))
    private_key_file.close()

    return signature
    # ����bytes���͵�ǩ��


def rsa_verify(signature, data, publicPemPath):
    # �öԷ���Կ�Է�������bytes��ǩ����str��У����Ϣ������ǩ

    public_key_file = open(publicPemPath, 'r')
    pub_key = RSA.importKey(public_key_file.read())
    hash_obj = my_hash(data)
    verifier = SV_PKCS1_v1_5.new(pub_key)
    public_key_file.close()

    return verifier.verify(hash_obj, base64.b64decode(signature))
    # ����һ��booleanֵ��ʾ�Ƿ�Ϸ�


def rsa_encrypt(publicPemPath, RSA_DecryptText):
    # ��str��RSA_DecryptText����

    with open(publicPemPath, 'r') as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        cipher = ED_PKCS1_v1_5.new(rsakey)

        RSA_EncrptText = base64.b64encode(cipher.encrypt(RSA_DecryptText.encode(encoding="utf-8")))
    print('RSA�����������ģ�', RSA_EncrptText)

    return RSA_EncrptText
    # ����bytes������


def rsa_decrypt(privatePemPath, RSA_EncrptText):
    # ��str��RSA���Ľ���

    with open(privatePemPath, 'r') as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        cipher = ED_PKCS1_v1_5.new(rsakey)
        RSA_DecryptText = cipher.decrypt(base64.b64decode(RSA_EncrptText), "ERROR")

    return RSA_DecryptText
    # ����bytes��RSA����


def my_hash(data):
    return MD5.new(data.encode('utf-8'))


"""
signature = rsa_sign('md5rsa', 'RSA_PrivateBob.pem')
print('ʹ��Bob˽Կ���ַ���"md5rsa"ǩ��', signature)
print('ʹ��Bob��Կ��ǩ�����', rsa_verify(signature, 'md5rsa', 'RSA_PublicBob.pem'))

RSA_EncryptText = "ZeDunh54R2i6BVwVw+XKhC2oMgWCFQ2rdBvDzbIn3H1Y4CrVhBSoQfI8rhFjLqCBAX/ug+thafon7niFss1wRDzgSAmzoYMA0VbuM8MCxBLVzCkbTd6rL0r3ZbnVAcIjZ4S2xGheUMFQoSBv6YV31BcZGTIrAV6mdfRIf+y5yuk=".encode('UTF-8')
print('Bob˽Կ���ܽ��', rsa_decrypt('RSA_PrivateBob.pem', RSA_EncryptText))
"""
