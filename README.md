# async-secure-com
用 python asyncio 异步编程实现的多用户加密即时通信工具，支持多用户群聊、文件上传下载
加密方案采用128位X25519椭圆曲线DH密钥交换 + 128位AES-GCM对称加密。用asynccmd实现命令行交互

运行服务器：

    python server_main.py -c server_config.json
    
运行客户端：

    python client_main.py -c client_config.json
    
    
