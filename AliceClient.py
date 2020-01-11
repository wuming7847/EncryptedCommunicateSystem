# coding:gbk
'''
Author:       无名Joker
Purpose:    客户端
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


def connectToServer(host, port):
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 创建socket对象用于连接服务端

    print("正在尝试与服务器", host, ":", port, "建立连接...")
    serverSocket.connect((host, port))
    print("连接成功")
    print()

    return serverSocket


if __name__ == "__main__":
    host = '127.0.0.1'
    port = 9999
    serverSocket = connectToServer(host, port)
    # 连接到服务器套接字

    global privatePemPath
    # 自己的RSA私钥文件
    global publicPemPath
    # 对方的RSA公钥文件
    privatePemPath = 'RSA_PrivateAlice.pem'
    publicPemPath = 'RSA_PublicBob.pem'

    UM.sendLegalInfoTo(serverSocket, privatePemPath, publicPemPath)
    # 向服务器发送自己的合法性校验信息
    legalServer = UM.readLegalInfoFrom(serverSocket, publicPemPath)
    # 校验服务器的合法性

    if(legalServer):
        # 校验对方身份合法时开始协商DH密钥以及后续通信

        DH_Group = 15
        # 生成DH算法公私钥对的参数
        DH_AliceClient, DH_PrivateAlice, DH_PublicAlice = DH.DH_Original(DH_Group)
        # 生成DHE对象及DH公私钥

        UM.RSA_EncryptSignatureTo(serverSocket, str(DH_Group), privatePemPath, publicPemPath)
        # 1.发送DH_Group给服务器

        UM.sendTo(serverSocket, DH_PublicAlice, "已向服务器发送客户端DH公钥")
        # 2.发送客户端DH公钥给服务器

        DH_PublicBob = UM.readFrom(serverSocket, '已接收到服务器DH公钥')
        # 3.接收服务器DH公钥
        print('服务器DH公钥', str(DH_PublicBob)[0:20])

        DH_FinalKey = DH.DH_FinalKeyGenerator(DH_AliceClient, int(DH_PublicBob))
        # 生成共享DH密钥

        print('开始通信...')
        print()

        TDES_Key = str(DH_FinalKey)[0:24]
        # 使用协商出的共享DH密钥的前24位作TDES密钥

        # 多线程实现边监听边发送
        clientSending = threading.Thread(target=UM.sendingThread, args=(serverSocket, TDES_Key, privatePemPath, publicPemPath), name='clientSendingThread')  
        clientReceiving = threading.Thread(target=UM.receivingThread, args=(serverSocket, TDES_Key, privatePemPath, publicPemPath), name='clientReceivingThread')

        clientSending.start()
        clientReceiving.start()

        clientSending.join()
        clientReceiving.join()

        print('通信已结束...')
    else:
        print("服务器不合法！已关闭连接")
    print('会话结束，已关闭连接')
