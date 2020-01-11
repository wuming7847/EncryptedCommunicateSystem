# coding:gbk
'''
Author:       ����Joker
Purpose:    ������
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

from Cryptography import RSA_SVED


def serverStart(host, port):
    # ���������������׽���

    mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ����socket�������ڶ����ṩ����
    mySocket.bind((host, port))
    # ���׽���

    print("������", host, ":", port, "������")

    mySocket.listen(5)
    # ����������������������Ŷ�

    return mySocket


def serverListening(mySocket):
    clientSocket, clientAddress = mySocket.accept()
    # �����ͻ������ӣ���ClientSocket����ͻ����׽��ֶ���addrΪ�ͻ����׽��ֵ�ַ
    print("�ͻ���: %s" % str(clientAddress), "�����ӵ�������")
    return clientSocket, clientAddress


def clientClose(clientSocket, clientAddress):
    clientSocket.close()
    print("�ͻ���: %s" % str(clientAddress), "�ѶϿ�����")


if __name__ == "__main__":
    host = '127.0.0.1'
    port = 9999
    mySocket = serverStart(host, port)

    global privatePemPath
    # �Լ���RSA˽Կ�ļ�
    global publicPemPath
    # �Է���RSA��Կ�ļ�
    privatePemPath = 'RSA_PrivateBob.pem'
    publicPemPath = 'RSA_PublicAlice.pem'

    clientSocket, clientAddress = serverListening(mySocket)
    # �ȴ��ͻ�������

    legalClient = UM.readLegalInfoFrom(clientSocket, publicPemPath)
    # У��ͻ��˵ĺϷ���
    UM.sendLegalInfoTo(clientSocket, privatePemPath, publicPemPath)
    # ��ͻ��˷����Լ��ĺϷ���У����Ϣ

    if(legalClient):
        # У��Է���ݺϷ�ʱ��ʼЭ��DH��Կ�Լ�����ͨ��

        legalDH_Group, RSA_DH_Group = UM.RSA_VerifyFrom(clientSocket, publicPemPath)
        RSA_DH_Group = RSA_DH_Group.replace("b'", '').replace("'", '')

        DH_Group = str(RSA_SVED.rsa_decrypt(privatePemPath, RSA_DH_Group)).replace("b'", '').replace("'", '')
        # 1.���ܵõ�bytes�Ϳͻ���ʹ�õ�DH_Group��Ȼ��תstr���淶�����ڽ���
        print('�ͻ���ʹ�õ�DH_GroupΪ��', DH_Group)

        DH_PublicAlice = UM.readFrom(clientSocket, "�ѽ��յ��ͻ���DH��Կ")
        # �������ӿͻ����׽��ֽ����乫Կ DH_PublicAlice
        print("�ͻ���DH��Կ��", DH_PublicAlice[0:20])

        DH_BobServer, DH_PrivateBob, DH_PublicBob = DH.DH_Original(int(DH_Group))
        # ������ʹ����ͬ��int��DH_Group����DHE����DH��˽Կ

        UM.sendTo(clientSocket, DH_PublicBob, "����ͻ��˷��ͷ�����DH��Կ")

        if legalDH_Group:
            # ���Ϸ�ʱ��ʼͨ��

            DH_FinalKey = DH.DH_FinalKeyGenerator(DH_BobServer, int(DH_PublicAlice))
            # ���������ɹ���DH��Կ

            TDES_Key = str(DH_FinalKey)[0:24]
            # ʹ��Э�̳��Ĺ���DH��Կ��ǰ24λ��TDES��Կ

            print('��ʼͨ��...')
            print()
            # ���߳�ʵ�ֱ߼����߷���
            serverSending = threading.Thread(target=UM.sendingThread, args=(clientSocket, TDES_Key, privatePemPath, publicPemPath), name='serverSendingThread')
            serverReceiving = threading.Thread(target=UM.receivingThread, args=(clientSocket, TDES_Key, privatePemPath, publicPemPath), name='serverSendingThread')

            serverSending.start()
            serverReceiving.start()

            serverSending.join()
            serverReceiving.join()

            print('ͨ���ѽ���...')
        else:
            print('�Ƿ��ͻ��ˣ��ѹر�����')
    else:
        print("�Ƿ��ͻ��ˣ��ѹر�����")
        clientSocket.close()

clientClose(clientSocket, clientAddress)
