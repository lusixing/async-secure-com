# async-secure-com
 
 
Python asyncio implemented asynchronous multi-client communication tool, support group chat, file hosting and transfer.

Encrypted with 128 bits x25519 elliptic curve with diffie hellman key exchange + 128 bits AES-GCM symmetric encryption.

Enable cli interaction with asynccmd package.

To install:

    python install requirements.txt

To run the server:

    python server_main.py -c server_config.json
    
To run the client:

    python client_main.py -c client_config.json
    
To register：

    reg ${username} ${password}
    
To login in:

    login ${username} ${password}
    
To send text message:

    send ${message}
    
To upload files:

    ul ${filepath}
    
To download files:

    dl ${filepath}
