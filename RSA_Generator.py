# coding:gbk
'''
Author:       ����Joker
Purpose:    ����RSA��˽Կ�Բ��洢
Date:          2019��12��31��
Arguments:
Outputs:    pem�ļ�
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
# �����������

rsa = RSA.generate(1024, random_generator)
# ���ɹ�˽Կ��

private_pem = rsa.exportKey()

with open('RSA_PrivateBob.pem', 'wb') as f:
    f.write(private_pem)

public_pem = rsa.publickey().exportKey()
with open('RSA_PublicBob.pem', 'wb') as f:
    f.write(public_pem)
# �������Σ�����Alice��Bob�Ĺ�˽Կ���ĸ�pem�ļ�
