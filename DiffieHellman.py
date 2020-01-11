# coding:gbk
'''
Author:       ����Joker
Purpose:    Diffie Hellman���ɹ�˽Կ��������Կ
Date:          2020��1��8��
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


import pyDHE


def DH_Original(group):
    # ����int��group�Զ�ѡ�������ͱ�ԭ��������DHE���󼰹�˽Կ��

    DH_Object = pyDHE.new(group)

    print("�������ɱ���DH��˽Կ...")
    DH_PublicKey = DH_Object.getPublicKey()
    # ���ɹ�Կ
    DH_PrivateKey = DH_Object.a
    # ����˽Կ

    print("����DH��Կ��", str(DH_PublicKey)[0:20])
    print("����DH˽Կ��", str(DH_PrivateKey)[0:20])

    return DH_Object, DH_PrivateKey, DH_PublicKey


def DH_FinalKeyGenerator(DH_Object, DH_OppositePublicKey):
    # DHE����ʹ�öԷ������Ĺ�Կ�������յĹ���DH��Կ
    DH_FinalKey = DH_Object.update(DH_OppositePublicKey)
    print("���������DH������Կ��", str(DH_FinalKey)[0:20])
    print()
    return DH_FinalKey
