# coding:gbk
'''
Author:       无名Joker
Purpose:    原始RSA方法，向中层模块提供签名和验签，加密和解密
Date:          2020年1月6日
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
# 用于SV和ED操作的cipher类不同！！！
from Crypto.Hash import MD5
import base64


def rsa_sign(data, privatePemPath):
    # 用自己私钥对str型data的MD5值进行签名

    private_key_file = open(privatePemPath, 'r')
    pri_key = RSA.importKey(private_key_file.read())
    signer = SV_PKCS1_v1_5.new(pri_key)
    hash_obj = my_hash(data)
    signature = base64.b64encode(signer.sign(hash_obj))
    private_key_file.close()

    return signature
    # 返回bytes类型的签名


def rsa_verify(signature, data, publicPemPath):
    # 用对方公钥对发送来的bytes型签名和str型校验信息进行验签

    public_key_file = open(publicPemPath, 'r')
    pub_key = RSA.importKey(public_key_file.read())
    hash_obj = my_hash(data)
    verifier = SV_PKCS1_v1_5.new(pub_key)
    public_key_file.close()

    return verifier.verify(hash_obj, base64.b64decode(signature))
    # 返回一个boolean值表示是否合法


def rsa_encrypt(publicPemPath, RSA_DecryptText):
    # 对str型RSA_DecryptText加密

    with open(publicPemPath, 'r') as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        cipher = ED_PKCS1_v1_5.new(rsakey)

        RSA_EncrptText = base64.b64encode(cipher.encrypt(RSA_DecryptText.encode(encoding="utf-8")))
    print('RSA加密生成密文：', RSA_EncrptText)

    return RSA_EncrptText
    # 返回bytes型密文


def rsa_decrypt(privatePemPath, RSA_EncrptText):
    # 对str型RSA密文解密

    with open(privatePemPath, 'r') as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        cipher = ED_PKCS1_v1_5.new(rsakey)
        RSA_DecryptText = cipher.decrypt(base64.b64decode(RSA_EncrptText), "ERROR")

    return RSA_DecryptText
    # 返回bytes型RSA明文


def my_hash(data):
    return MD5.new(data.encode('utf-8'))


"""
signature = rsa_sign('md5rsa', 'RSA_PrivateBob.pem')
print('使用Bob私钥对字符串"md5rsa"签名', signature)
print('使用Bob公钥验签结果：', rsa_verify(signature, 'md5rsa', 'RSA_PublicBob.pem'))

RSA_EncryptText = "ZeDunh54R2i6BVwVw+XKhC2oMgWCFQ2rdBvDzbIn3H1Y4CrVhBSoQfI8rhFjLqCBAX/ug+thafon7niFss1wRDzgSAmzoYMA0VbuM8MCxBLVzCkbTd6rL0r3ZbnVAcIjZ4S2xGheUMFQoSBv6YV31BcZGTIrAV6mdfRIf+y5yuk=".encode('UTF-8')
print('Bob私钥解密结果', rsa_decrypt('RSA_PrivateBob.pem', RSA_EncryptText))
"""
