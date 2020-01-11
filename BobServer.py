# coding:gbk
'''
Author:       无名Joker
Purpose:    服务器
Date:          2019年12月31日
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
# 提高代码复用度的中层模块，内部封装了大多数方法

from Cryptography import DiffieHellman as DH
# DH算法生成公私钥对及协商共享密钥

from Cryptography import RSA_SVED


def serverStart(host, port):
    # 启动服务器并绑定套接字

    mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 创建socket对象用于对外提供连接
    mySocket.bind((host, port))
    # 绑定套接字

    print("服务器", host, ":", port, "已启动")

    mySocket.listen(5)
    # 设置最大连接数，超过后排队

    return mySocket


def serverListening(mySocket):
    clientSocket, clientAddress = mySocket.accept()
    # 建立客户端连接，用ClientSocket代表客户端套接字对象，addr为客户端套接字地址
    print("客户端: %s" % str(clientAddress), "已连接到服务器")
    return clientSocket, clientAddress


def clientClose(clientSocket, clientAddress):
    clientSocket.close()
    print("客户端: %s" % str(clientAddress), "已断开连接")


if __name__ == "__main__":
    host = '127.0.0.1'
    port = 9999
    mySocket = serverStart(host, port)

    global privatePemPath
    # 自己的RSA私钥文件
    global publicPemPath
    # 对方的RSA公钥文件
    privatePemPath = 'RSA_PrivateBob.pem'
    publicPemPath = 'RSA_PublicAlice.pem'

    clientSocket, clientAddress = serverListening(mySocket)
    # 等待客户端连接

    legalClient = UM.readLegalInfoFrom(clientSocket, publicPemPath)
    # 校验客户端的合法性
    UM.sendLegalInfoTo(clientSocket, privatePemPath, publicPemPath)
    # 向客户端发送自己的合法性校验信息

    if(legalClient):
        # 校验对方身份合法时开始协商DH密钥以及后续通信

        legalDH_Group, RSA_DH_Group = UM.RSA_VerifyFrom(clientSocket, publicPemPath)
        RSA_DH_Group = RSA_DH_Group.replace("b'", '').replace("'", '')

        DH_Group = str(RSA_SVED.rsa_decrypt(privatePemPath, RSA_DH_Group)).replace("b'", '').replace("'", '')
        # 1.解密得到bytes型客户端使用的DH_Group，然后转str并规范化便于解密
        print('客户端使用的DH_Group为：', DH_Group)

        DH_PublicAlice = UM.readFrom(clientSocket, "已接收到客户端DH公钥")
        # 服务器从客户端套接字接收其公钥 DH_PublicAlice
        print("客户端DH公钥：", DH_PublicAlice[0:20])

        DH_BobServer, DH_PrivateBob, DH_PublicBob = DH.DH_Original(int(DH_Group))
        # 服务器使用相同的int型DH_Group生成DHE对象及DH公私钥

        UM.sendTo(clientSocket, DH_PublicBob, "已向客户端发送服务器DH公钥")

        if legalDH_Group:
            # 均合法时开始通信

            DH_FinalKey = DH.DH_FinalKeyGenerator(DH_BobServer, int(DH_PublicAlice))
            # 服务器生成共享DH密钥

            TDES_Key = str(DH_FinalKey)[0:24]
            # 使用协商出的共享DH密钥的前24位作TDES密钥

            print('开始通信...')
            print()
            # 多线程实现边监听边发送
            serverSending = threading.Thread(target=UM.sendingThread, args=(clientSocket, TDES_Key, privatePemPath, publicPemPath), name='serverSendingThread')
            serverReceiving = threading.Thread(target=UM.receivingThread, args=(clientSocket, TDES_Key, privatePemPath, publicPemPath), name='serverSendingThread')

            serverSending.start()
            serverReceiving.start()

            serverSending.join()
            serverReceiving.join()

            print('通信已结束...')
        else:
            print('非法客户端！已关闭连接')
    else:
        print("非法客户端！已关闭连接")
        clientSocket.close()

clientClose(clientSocket, clientAddress)
