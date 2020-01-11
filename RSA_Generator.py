# coding:gbk
'''
Author:       无名Joker
Purpose:    生成RSA公私钥对并存储
Date:          2019年12月31日
Arguments:
Outputs:    pem文件
Dependencies:

History:
--------------------------------------------------------------
Date:
Author:
Modification:
--------------------------------------------------------------
'''
from Crypto import Random
from Crypto.PublicKey import RSA

random_generator = Random.new().read
# 随机数生成器

rsa = RSA.generate(1024, random_generator)
# 生成公私钥对

private_pem = rsa.exportKey()

with open('RSA_PrivateBob.pem', 'wb') as f:
    f.write(private_pem)

public_pem = rsa.publickey().exportKey()
with open('RSA_PublicBob.pem', 'wb') as f:
    f.write(public_pem)
# 运行两次，生成Alice和Bob的公私钥共四个pem文件
