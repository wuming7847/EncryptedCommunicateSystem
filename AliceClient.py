# coding:gbk
'''
Author:       ����Joker
Purpose:    �ͻ���
Date:          2019��12��31��
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


import socket
import threading


from Cryptography import UniversalMethods as UM
# ��ߴ��븴�öȵ��в�ģ�飬�ڲ���װ�˴��������

from Cryptography import DiffieHellman as DH
# DH�㷨���ɹ�˽Կ�Լ�Э�̹�����Կ


def connectToServer(host, port):
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ����socket�����������ӷ����

    print("���ڳ����������", host, ":", port, "��������...")
    serverSocket.connect((host, port))
    print("���ӳɹ�")
    print()

    return serverSocket


if __name__ == "__main__":
    host = '127.0.0.1'
    port = 9999
    serverSocket = connectToServer(host, port)
    # ���ӵ��������׽���

    global privatePemPath
    # �Լ���RSA˽Կ�ļ�
    global publicPemPath
    # �Է���RSA��Կ�ļ�
    privatePemPath = 'RSA_PrivateAlice.pem'
    publicPemPath = 'RSA_PublicBob.pem'

    UM.sendLegalInfoTo(serverSocket, privatePemPath, publicPemPath)
    # ������������Լ��ĺϷ���У����Ϣ
    legalServer = UM.readLegalInfoFrom(serverSocket, publicPemPath)
    # У��������ĺϷ���

    if(legalServer):
        # У��Է���ݺϷ�ʱ��ʼЭ��DH��Կ�Լ�����ͨ��

        DH_Group = 15
        # ����DH�㷨��˽Կ�ԵĲ���
        DH_AliceClient, DH_PrivateAlice, DH_PublicAlice = DH.DH_Original(DH_Group)
        # ����DHE����DH��˽Կ

        UM.RSA_EncryptSignatureTo(serverSocket, str(DH_Group), privatePemPath, publicPemPath)
        # 1.����DH_Group��������

        UM.sendTo(serverSocket, DH_PublicAlice, "������������Ϳͻ���DH��Կ")
        # 2.���Ϳͻ���DH��Կ��������

        # legalDH_PublicBob, RSA_DH_PublicBob = UM.RSA_VerifyFrom(serverSocket, publicPemPath)
        DH_PublicBob = UM.readFrom(serverSocket, '�ѽ��յ�������DH��Կ')
        # 3.���շ�����DH��Կ
        print('������DH��Կ', DH_PublicBob)

        DH_FinalKey = DH.DH_FinalKeyGenerator(DH_AliceClient, int(DH_PublicBob))
        # ���ɹ���DH��Կ

        print('��ʼͨ��...')
        print()

        TDES_Key = str(DH_FinalKey)[0:24]
        # ʹ��Э�̳��Ĺ���DH��Կ��ǰ24λ��TDES��Կ

        # ���߳�ʵ�ֱ߼����߷���
        clientSending = threading.Thread(target=UM.sendingThread, args=(serverSocket, TDES_Key, privatePemPath, publicPemPath), name='clientSendingThread')  
        clientReceiving = threading.Thread(target=UM.receivingThread, args=(serverSocket, TDES_Key, privatePemPath, publicPemPath), name='clientReceivingThread')

        clientSending.start()
        clientReceiving.start()

        clientSending.join()
        clientReceiving.join()

        print('ͨ���ѽ���...')
    else:
        print("���������Ϸ����ѹر�����")
    print('�Ự�������ѹر�����')
