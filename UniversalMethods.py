# coding:gbk
'''
Author:       ����Joker
Purpose:    Ϊ����ߴ��븴�öȣ��ع��󹩿ͻ��˺ͷ��������õ��в�ģ��
Date:          2020��1��7��
Arguments:
Outputs:    timeStamp() ����ʱ���
            sendTo(theSocket, message, hint=None) ��Է��׽��ַ�����Ϣ
            readFrom(theSocket, hint=None) �ӶԷ��׽��ֽ�����Ϣ
            sendLegalInfoTo(theSocket, privatePemPath, publicPemPath) ����������öԷ����кϷ���У��
            readLegalInfoFrom(theSocket, publicPemPath) У��Է���ݵĺϷ���
            RSA_SignatureTo(theSocket, RSA_DecryptText, privatePemPath) ��Է�����ʱ�����ǩ����У����Ϣ
            RSA_VerifyFrom(theSocket, publicPemPath) У��Է�������ʱ�����ǩ����У����Ϣ
            communicatePackageReceiver(theSocket, TDES_Key, publicPemPath) ����ͨ�����ݰ�
            communicatePackageReceiver(theSocket, TDES_Key, publicPemPath) ����ͨ�����ݰ�
            sendingThread(theSocket, TDES_Key, privatePemPath) ����ͨ�����ݰ����̷߳���
            receivingThread(theSocket, TDES_Key, publicPemPath) ����ͨ�����ݰ����̷߳���
Dependencies:

History:
--------------------------------------------------------------
Date:
Author:
Modification:
--------------------------------------------------------------
'''


import random
import time


from Cryptography import RSA_SVED
# ʵ��RSA ǩ�� ��ǩ ���� ���ܵĵײ�ģ��

from Cryptography import TripleDES
# ʵ��TDES�㷨�ӽ��ܵĵײ�ģ��


def timeStamp():
    # ����ʱ���
    currentTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    return currentTime
    # ����str��ʱ����磺2020-01-08 23:28:12


def sendTo(theSocket, message, hint=None):
    # ���׽��ֶ�����str��message�����һЩ˵����Ϣ

    message = str(message).encode('utf-8')
    theSocket.send(message)
    if hint is not None:
        print(hint)


def readFrom(theSocket, hint=None):
    # ���׽��ֶ������Ϣ�����һЩ˵����Ϣ

    message = theSocket.recv(1024).decode('utf-8')
    if hint is not None:
        print(hint)

    if (message != ''):

        return message
        # ���ض�����str���͵�message
    else:
        readtheSocketError = Exception('δ�ӶԷ������յ���Ϣ��')
        raise readtheSocketError


def sendLegalInfoTo(theSocket, privatePemPath, publicPemPath):
    # ��Է������������У����Ϣ���кϷ�����֤

    LegalMessage = str(random.randint(1000, 9999))
    RSA_EncryptSignatureTo(theSocket, LegalMessage, privatePemPath, publicPemPath)
    # ���öԷ�RSA��Կ�����ɵ����������
    # Ȼ�����Լ���˽Կ��RSA���ĵ�MD5ֵǩ��
    # ����ʱ�����ǩ����RSA���ķ���ȥ


def readLegalInfoFrom(theSocket, publicPemPath):
    # �ԶԷ������������Ϣ���кϷ���У��

    legal = RSA_VerifyFrom(theSocket, publicPemPath)
    # �յ��Է�ʱ���
    # �յ��Է�ǩ�����öԷ��Ĺ�Կ��ǩ���õ�ǩ���е�MD5ֵ
    # ��һͬ������RSA���ģ�У����Ϣ����MD5
    # �������MD5ֵ�������֤�Է�Ϊ�Ϸ�

    return legal
    # �����Ƿ�Ϸ�


def RSA_EncryptSignatureTo(theSocket, RSA_DecryptText, privatePemPath, publicPemPath):
    # ����str���͵�RSA_DecryptText

    # ���öԷ���Կ���ܣ��ٶ����ĵ�MD5ֵǩ��
    # �����ǩ������ܻᵼ�¼��ܵ�����̫�����޷����ܣ�����

    print()
    sendTo(theSocket, timeStamp(), '�ѷ���ʱ���')

    print('�����öԷ�RSA��Կ���ܣ�����ǰΪ��', RSA_DecryptText)
    RSA_EncryptText = str(RSA_SVED.rsa_encrypt(publicPemPath, RSA_DecryptText))
    # ���öԷ�RSA��Կ��������str��RSA����

    print('�����ñ���RSA˽Կ������ǩ��')
    RSA_Signature = RSA_SVED.rsa_sign(RSA_EncryptText, privatePemPath)
    # �ٶ�RSA����ǩ������bytes���͵�RSAǩ��

    sendTo(theSocket, RSA_Signature, '�ѷ���RSAǩ����' + str(RSA_Signature))
    sendTo(theSocket, RSA_EncryptText, '�ѷ���У����Ϣ��' + RSA_EncryptText)
    print()


def RSA_VerifyFrom(theSocket, publicPemPath):
    # ��ǩ

    print()
    timeStamp = readFrom(theSocket)
    print('�Է���', timeStamp, '�������ݰ�')

    RSA_Signature = readFrom(theSocket, '���յ��Է���RSAǩ��').replace("b'", '').replace("'", '').encode('UTF-8')
    # ���������е��ѿ�
    # ���յ�str�͵�ǩ��b'xxx'��ȡ���м��str xxx��Ȼ����תΪbytes����

    print('ǩ��Ϊ��', RSA_Signature)

    RSA_EncryptText = readFrom(theSocket, '���յ�У����Ϣ')
    # str��У����Ϣ
    print('У����ϢΪ��', RSA_EncryptText)

    legal = RSA_SVED.rsa_verify(RSA_Signature, RSA_EncryptText, publicPemPath)
    print('�Է�����Ƿ�Ϸ���', legal)
    print()

    return legal, RSA_EncryptText
    # ����booleanֵ��ʾ�Ƿ�Ϸ���str�͵�У����Ϣ���� RSA����


def communicatePackageSender(theSocket, TDES_Key, privatePemPath, publicPemPath, TDES_DecryptText):
    # ��str�͵�ԭʼ����TDES_DecryptText����һϵ�в����󷢰�

    prpcryptObject = TripleDES.prpcrypt()
    # �½�TDES����

    TDES_EncryptText = TripleDES.TDES_Encrypt(prpcryptObject, TDES_DecryptText, TDES_Key)
    # ����ԭʼ��������str�� TDES����

    RSA_EncryptSignatureTo(theSocket, TDES_EncryptText, privatePemPath, publicPemPath)
    # ��TDES�����öԷ���Կ���ܺ�ǩ������ͬУ����Ϣһ�����͸�������

    print()
    # ������һ�����ݰ�����


def communicatePackageReceiver(theSocket, TDES_Key, privatePemPath, publicPemPath):
    # ������նԷ�������ʱ�����ǩ����TDES����
    # ��ǩ������У�飬������ٽ���TDES����

    legalClient, RSA_DecryptText = RSA_VerifyFrom(theSocket, publicPemPath)
    # ����ֵΪboolean��ֵ�Ƿ�Ϸ���str��У����Ϣ

    RSA_DecryptText = RSA_DecryptText.replace("b'", '').replace("'", '')
    # ��Ϊstr�ͣ��淶������ʹ��rsa_decrypt()����

    if legalClient:
        # ����Է��Ϸ�������Ľ��н���

        TDES_EncryptText = str(RSA_SVED.rsa_decrypt(privatePemPath, RSA_DecryptText))
        # ���Լ���˽Կ����RSA���ĵõ�TDES����
        # ����bytes��TDES���ĺ�תΪstr

        TDES_EncryptText = str(TDES_EncryptText).replace("b'", '').replace("'", '')
        # str�ͣ���TDES���Ĺ淶������TDES_Decrypt()����

        prpcryptBob = TripleDES.prpcrypt()
        # �½�TDES����

        TDES_DecryptText = TripleDES.TDES_Decrypt(prpcryptBob, TDES_EncryptText, TDES_Key)
        # ���ܵõ�str�͵�TDES����

        return TDES_DecryptText
        # ����str�͵�TDES����


def sendingThread(theSocket, TDES_Key, privatePemPath, publicPemPath):
    # ��ģ�����̵߳��õķ��ͺ���

    while True:
        TDES_DecryptText = input('����Ӣ�Ļ�����WMend�������ͣ�')
        communicatePackageSender(theSocket, TDES_Key, privatePemPath, publicPemPath, TDES_DecryptText)
        if TDES_DecryptText == 'WMend':
            # �����߳̽���
            print('�����߳̽���')
            print()
            break


def receivingThread(theSocket, TDES_Key, privatePemPath, publicPemPath):
    # ��ģ�����̵߳��õļ�������

    while True:
        TDES_DecryptText = communicatePackageReceiver(theSocket, TDES_Key, privatePemPath, publicPemPath)
        if TDES_DecryptText[0:5] == 'WMend':
            # �����߳̽���
            print('�����߳̽���')
            print()
            break
