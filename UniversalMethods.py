# coding:gbk
'''
Author:       无名Joker
Purpose:    为了提高代码复用度，重构后供客户端和服务器共用的中层模块
Date:          2020年1月7日
Arguments:
Outputs:    timeStamp() 生成时间戳
            sendTo(theSocket, message, hint=None) 向对方套接字发送消息
            readFrom(theSocket, hint=None) 从对方套接字接收消息
            sendLegalInfoTo(theSocket, privatePemPath, publicPemPath) 生成随机数让对方进行合法性校验
            readLegalInfoFrom(theSocket, publicPemPath) 校验对方身份的合法性
            RSA_SignatureTo(theSocket, RSA_DecryptText, privatePemPath) 向对方发送时间戳，签名，校验信息
            RSA_VerifyFrom(theSocket, publicPemPath) 校验对方发来的时间戳，签名，校验信息
            communicatePackageReceiver(theSocket, TDES_Key, publicPemPath) 发送通信数据包
            communicatePackageReceiver(theSocket, TDES_Key, publicPemPath) 接收通信数据包
            sendingThread(theSocket, TDES_Key, privatePemPath) 发送通信数据包的线程方法
            receivingThread(theSocket, TDES_Key, publicPemPath) 接收通信数据包的线程方法
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
# 实现RSA 签名 验签 加密 解密的底层模块

from Cryptography import TripleDES
# 实现TDES算法加解密的底层模块


def timeStamp():
    # 生成时间戳
    currentTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    return currentTime
    # 返回str型时间戳如：2020-01-08 23:28:12


def sendTo(theSocket, message, hint=None):
    # 向套接字对象发送str型message，输出一些说明信息

    message = str(message).encode('utf-8')
    theSocket.send(message)
    if hint is not None:
        print(hint)


def readFrom(theSocket, hint=None):
    # 从套接字对象读消息，输出一些说明信息

    message = theSocket.recv(1024).decode('utf-8')
    if hint is not None:
        print(hint)

    if (message != ''):

        return message
        # 返回读到的str类型的message
    else:
        readtheSocketError = Exception('未从对方处接收到消息！')
        raise readtheSocketError


def sendLegalInfoTo(theSocket, privatePemPath, publicPemPath):
    # 向对方发送随机数等校验信息进行合法性认证

    LegalMessage = str(random.randint(1000, 9999))
    RSA_EncryptSignatureTo(theSocket, LegalMessage, privatePemPath, publicPemPath)
    # 先用对方RSA公钥对生成的随机数加密
    # 然后用自己的私钥对RSA密文的MD5值签名
    # 最后把时间戳、签名、RSA密文发过去


def readLegalInfoFrom(theSocket, publicPemPath):
    # 对对方的随机数等信息进行合法性校验

    legal = RSA_VerifyFrom(theSocket, publicPemPath)
    # 收到对方时间戳
    # 收到对方签名后用对方的公钥解签，得到签名中的MD5值
    # 对一同发来的RSA密文（校验信息）作MD5
    # 如果两个MD5值相等则验证对方为合法

    return legal
    # 返回是否合法


def RSA_EncryptSignatureTo(theSocket, RSA_DecryptText, privatePemPath, publicPemPath):
    # 输入str类型的RSA_DecryptText

    # 先用对方公钥加密，再对密文的MD5值签名
    # 如果先签名后加密会导致加密的输入太长而无法加密！！！

    print()
    sendTo(theSocket, timeStamp(), '已发送时间戳')

    print('正在用对方RSA公钥加密，加密前为：', RSA_DecryptText)
    RSA_EncryptText = str(RSA_SVED.rsa_encrypt(publicPemPath, RSA_DecryptText))
    # 先用对方RSA公钥加密生成str型RSA密文

    print('正在用本机RSA私钥对密文签名')
    RSA_Signature = RSA_SVED.rsa_sign(RSA_EncryptText, privatePemPath)
    # 再对RSA密文签名生成bytes类型的RSA签名

    sendTo(theSocket, RSA_Signature, '已发送RSA签名：' + str(RSA_Signature))
    sendTo(theSocket, RSA_EncryptText, '已发送校验信息：' + RSA_EncryptText)
    print()


def RSA_VerifyFrom(theSocket, publicPemPath):
    # 验签

    print()
    timeStamp = readFrom(theSocket)
    print('对方在', timeStamp, '发来数据包')

    RSA_Signature = readFrom(theSocket, '已收到对方的RSA签名').replace("b'", '').replace("'", '').encode('UTF-8')
    # 这个处理的有点难看
    # 把收到str型的签名b'xxx'提取出中间的str xxx，然后再转为bytes类型

    print('签名为：', RSA_Signature)

    RSA_EncryptText = readFrom(theSocket, '已收到校验信息')
    # str型校验信息
    print('校验信息为：', RSA_EncryptText)

    legal = RSA_SVED.rsa_verify(RSA_Signature, RSA_EncryptText, publicPemPath)
    print('对方身份是否合法？', legal)
    print()

    return legal, RSA_EncryptText
    # 返回boolean值表示是否合法，str型的校验信息，即 RSA密文


def communicatePackageSender(theSocket, TDES_Key, privatePemPath, publicPemPath, TDES_DecryptText):
    # 对str型的原始明文TDES_DecryptText进行一系列操作后发包

    prpcryptObject = TripleDES.prpcrypt()
    # 新建TDES对象

    TDES_EncryptText = TripleDES.TDES_Encrypt(prpcryptObject, TDES_DecryptText, TDES_Key)
    # 加密原始明文生成str型 TDES密文

    RSA_EncryptSignatureTo(theSocket, TDES_EncryptText, privatePemPath, publicPemPath)
    # 对TDES密文用对方公钥加密后签名，连同校验信息一并发送给服务器

    print()
    # 发送完一个数据包后换行


def communicatePackageReceiver(theSocket, TDES_Key, privatePemPath, publicPemPath):
    # 按序接收对方发来的时间戳，签名，TDES密文
    # 对签名进行校验，无误后再进行TDES解密

    legalClient, RSA_DecryptText = RSA_VerifyFrom(theSocket, publicPemPath)
    # 返回值为boolean型值是否合法和str型校验信息

    RSA_DecryptText = RSA_DecryptText.replace("b'", '').replace("'", '')
    # 仍为str型，规范化便于使用rsa_decrypt()解密

    if legalClient:
        # 如果对方合法则对密文进行解密

        TDES_EncryptText = str(RSA_SVED.rsa_decrypt(privatePemPath, RSA_DecryptText))
        # 用自己的私钥解密RSA密文得到TDES密文
        # 返回bytes型TDES密文后转为str

        TDES_EncryptText = str(TDES_EncryptText).replace("b'", '').replace("'", '')
        # str型，将TDES密文规范化便于TDES_Decrypt()解密

        prpcryptBob = TripleDES.prpcrypt()
        # 新建TDES对象

        TDES_DecryptText = TripleDES.TDES_Decrypt(prpcryptBob, TDES_EncryptText, TDES_Key)
        # 解密得到str型的TDES明文

        return TDES_DecryptText
        # 返回str型的TDES明文


def sendingThread(theSocket, TDES_Key, privatePemPath, publicPemPath):
    # 主模块中线程调用的发送函数

    while True:
        TDES_DecryptText = input('输入英文或输入WMend结束发送：')
        communicatePackageSender(theSocket, TDES_Key, privatePemPath, publicPemPath, TDES_DecryptText)
        if TDES_DecryptText == 'WMend':
            # 发送线程结束
            print('发送线程结束')
            print()
            break


def receivingThread(theSocket, TDES_Key, privatePemPath, publicPemPath):
    # 主模块中线程调用的监听函数

    while True:
        TDES_DecryptText = communicatePackageReceiver(theSocket, TDES_Key, privatePemPath, publicPemPath)
        if TDES_DecryptText[0:5] == 'WMend':
            # 监听线程结束
            print('监听线程结束')
            print()
            break
