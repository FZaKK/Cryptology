# cryptology
cryptology course in NKU

1. 目前已经全部完成，可以直接使用测试文件文件夹来进行测试，可以使用的指令为encrypt（AES加密）、decrypt（AES解密）、send（发送文件）、quit（退出程序）、request（向对方请求AES密钥，并发送RSA公钥）和verify（响应，验证request请求）
2. 对于通讯双方而言，唯一的不同点就是request请求的发送方是可以不同的，当一方发送request命令后，那么本次通讯双方的AES密钥就是接收方的AES密钥，但是双方都是可以进行AES加密、解密以及双向通讯发送的。
3. 如果想要进一步提高安全性的话，可以在每次发送的TCP Message的基础上再进行一次RSA加解密。
4. 最后就是针对测试文件的部分，在encrypt和decrypt部分注释了针对实际文件（如字符串txt文本、jpg、png图片等）的加密与解密函数，那一部分可以启用，在测试程序文件夹中给出的test测试文件是为了展现完整的保密通讯流程而设置的数值文件。


其余课程任务内容，后续再传吧（如果还能想起来的话...）
