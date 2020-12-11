import sys
sys.path.append("..")

import os
import asyncio

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from misc.encryption_misc import *
import misc.db_backend as db_backend
import logging
import json
import argparse


class Server:
    def __init__(self, server_config_path):
        self.main_loop = asyncio.get_event_loop()
        self.server_private_key = X25519PrivateKey.generate()
        self.server_public_key = self.server_private_key.public_key()
        self.server_users = dict()
        self.server_admin = dict()
        self.server_blacklist = set()
        self.logger = logging.getLogger(__name__)
        self.server_config_path = server_config_path
        self.server_config = json.loads(open(self.server_config_path, 'r').read())
        self.db_connection = db_backend.db_connection(self.server_config)

        asyncio.set_event_loop(self.main_loop)
        logging.basicConfig(level=logging.DEBUG)

    def validate_username(self, username):
            if len(username) > 32 or len(username) < 4:
                return False
            illegal_chars = {'!', '?', '(', ')' '{', '}', '=', '~', '/', '\\', '.', ':', ','}
            for char in username:
                if char in illegal_chars:
                    return False
            return True


class Client_handler:
    def __init__(self, reader, writer):
        self.writer = writer
        self.reader = reader
        self.handshake = False
        self.login = False
        self.username = None
        self.share_key = None
        self.iv = None
        self.pilot = None
        self.msg_queue = asyncio.Queue(maxsize=100)
        self.ack = asyncio.Event()
        self.incoming = None
        self.file_handler = None
        self.peername = self.writer.get_extra_info('peername')
        self.server = None

    async def respond_handshake(self):
        while not self.handshake:
            try:
                handshake_request = await self.reader.read(512)
                handshake_data = extract_data(handshake_request)
                user_public_key_serial = handshake_data['public_key'].encode()
                user_public_key = serialization.load_pem_public_key(user_public_key_serial)
                self.share_key = self.server.server_private_key.exchange(user_public_key)
                self.iv = bytes(handshake_data['iv'], encoding="utf8")
                server_public_key_serial = self.server.server_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                          format=serialization.PublicFormat.SubjectPublicKeyInfo)
                response = {
                    'success': True,
                    'server_public_key': str(server_public_key_serial, encoding="utf8")
                }
                response_serial = bytes(json.dumps(response), encoding='utf-8')
                self.writer.write(response_serial)
                await self.writer.drain()
                self.handshake = True
                self.server.logger.info(f"{self.peername[0]}:{self.peername[1]} handshake successful")
                break
            except:
                self.server.logger.debug(f"{self.peername[0]}:{self.peername[1]} handshake fail")

    def reset_pw_handler(self, request):
        if not self.login:
            res = {'status': 'fail', 'message': '未登陆'}
        else:
            payload = extract_enc_data(self, request)
            res = self.server.db_connection.reset_password(username=self.username, new_password=payload["new_password"])
        self.msg_queue.put_nowait((res, 0))

    def registration_handler(self, request):
        if not self.server.server_config["allow_registration"]:
            res = {'status': 'fail', 'message': '注册已关闭'}
            self.msg_queue.put_nowait((res, 0))
            return

        payload = extract_enc_data(self, request)

        if self.server.validate_username(payload['username']):
            res = self.server.db_connection.confirm_registration(username=payload["username"], password=payload["password"])
            if res['status'] == 'success':
                self.login = True
                self.username = payload["username"]
                self.server.server_users[self.username] = self
                msg = {
                    'from': 'system',
                    'message': f'{self.username} 新注册'
                }
                for user in self.server.server_users:
                    user_handler = self.server.server_users[user]
                    user_handler.msg_queue.put_nowait((msg, 0))

                for admin in self.server.server_admin:
                    user_handler = self.server.server_admin[admin]
                    user_handler.msg_queue.put_nowait((msg, 0))
        else:
            res = {'status': 'fail', 'msg': '用户名无效'}
        self.msg_queue.put_nowait((res, 0))

    def login_handler(self, request):
        if len(self.server.server_users) >= int(self.server.server_config["max_connection"]):
            res = {'status': 'fail', 'message': '已达到最大连接数'}
            self.msg_queue.put_nowait((res, 0))
            return

        payload = extract_enc_data(self, request)

        username = payload['username']
        password = payload['password']
        if self.server.db_connection.verify_login(username, password):
            if username in self.server.server_blacklist:
                res = {'status': 'fail', 'message': '用户被封禁'}
                self.msg_queue.put_nowait((res, 0))
                return
            res = {'status': 'success', 'message': '登录成功'}
            self.login = True
            self.username = username
            role = self.server.db_connection.get_role(username)
            if role == "user":
                self.server.server_users[self.username] = self  # !!!!!!!!!!!!
            elif role == "administrator":
                self.server.server_admin[self.username] = self

            self.server.logger.info(f'{self.username} 上线')

            msg = {
                'from': 'system',
                'message': f'{self.username} 上线'
            }

            for user in self.server.server_users:
                server = self.server.server_users[user]
                server.msg_queue.put_nowait((msg, 0))
            for admin in self.server.server_admin:
                server = self.server.server_admin[admin]
                server.msg_queue.put_nowait((msg, 0))
        else:
            res = {'status': 'fail', 'message': '登录失败，用户名或密码错误'}
        self.msg_queue.put_nowait((res, 0))

    def quit_handler(self, arg):
        #if self.login:
            msg = {
                'from': 'system',
                'message': f'{self.username} 退出'
            }
            for user in self.server.server_users:
                server = self.server.server_users[user]
                server.msg_queue.put_nowait((msg, 0))

            for admin in self.server.server_admin:
                server = self.server.server_admin[admin]
                server.msg_queue.put_nowait((msg, 0))

            self.writer.close()

            if self.username in self.server.server_users:
                del self.server.server_users[self.username]
            else:
                del self.server.server_admin[self.username]

    def kick_handler(self, request):
        if self.username not in self.server.server_admin:
            res = {'status': 'fail', 'message': f'无权限'}

        else:
            if "tag" in request:
                payload = extract_enc_data(self, request)
            else:
                payload = request
            if payload['username'] in self.server.server_users:
                del self.server.server_users[payload['username']]
                self.server.server_blacklist.add(payload['username'])
                res = {'status': 'success', 'message': f'已封禁用户'}
            else:
                res = {'status': 'fail', 'message': f'用户不存在'}
        return res

    def upload_handler(self, request):
        if not os.path.exists(self.server.server_config["file_folder"]):
            os.mkdir(self.server.server_config["file_folder"])
        if self.server.server_config["allow_upload"] == "True" \
                and not os.path.exists(os.path.join(self.server.server_config["file_folder"],request["fname"])):
            reply = {'allow_ul': 'y'}
            self.incoming = request["fname"]
            self.file_handler = open(os.path.join(self.server.server_config["file_folder"], request["fname"]), 'ab')
        else:
            reply = {'allow_ul': 'n'}
        self.msg_queue.put_nowait((reply, 0))

    def list_files_handler(self, arg):
        path = self.server.server_config["file_folder"]
        fnames = os.listdir(path)
        fsizes = [(fname, os.path.getsize(os.path.join(path, fname))) for fname in fnames]
        msg = {"message": str(fsizes)}
        self.msg_queue.put_nowait((msg, 1))

    async def download_handler(self, request):
        fname = request["fname"]
        fpath = os.path.join(self.server.server_config["file_folder"], fname)
        if not os.path.exists(fpath):
            reply = {'allow_dl': 'n'}
            self.msg_queue.put_nowait((reply, 0))
        else:
            fsize = os.path.getsize(fpath)
            reply = {'allow_dl': 'y', 'fsize': fsize}
            self.msg_queue.put_nowait((reply, 0))

            file_handler = open(fpath, 'rb')
            chunk_size = 8192
            while True:
                chunk = file_handler.read(chunk_size)
                if not chunk:
                    break
                payload = {"chunk_data": str(b64encode(chunk), encoding='utf-8')}
                await self.msg_queue.put((payload, 1))
            EOF = {"chunk_data": "EOF"}
            await self.msg_queue.put((EOF, 1))

    async def broadcast_handler(self, request):
        if self.server.server_config["allow_anonymous"] != "True":
            if not self.login:
                res = {'status': 'fail', 'message': f'未登陆'}
                self.msg_queue.put_nowait((res, 0))
                return
        else:
            if self.username is None:
                self.username = "anonymous_user" + str(len(self.server.server_users) + 1)
                self.server.server_users[self.username] = self

        if "tag" in request:
            payload = extract_enc_data(self, request)
        else:
            payload = request

        msg = {
            'from': self.username,
            'message': payload["message"]
        }
        for username in self.server.server_users:
            client: Client_handler = self.server.server_users[username]
            client.msg_queue.put_nowait((msg, 1))

        for admin in self.server.server_admin:
            client: Client_handler = self.server.server_admin[admin]
            client.msg_queue.put_nowait((msg, 1))

    async def sender(self):
        try:
            while True:
                send_task = await self.msg_queue.get()
                message = send_task[0]
                message_enc = serialize_enc_data(self, message)
                message_serial = bytes(message_enc, encoding='utf-8')

                w_size = 128
                if send_task[1] == 0:
                    self.writer.write(message_serial)
                    await self.writer.drain()
                elif send_task[1] == 1:
                    pilot_data = (w_size, len(message_serial))
                    pilot_payload = {"header": "pilot", "pilot_data": pilot_data}

                    pilot_message = serialize_enc_data(self, payload=pilot_payload)
                    pilot_message_serial = bytes(pilot_message, encoding='utf-8')

                    self.writer.write(pilot_message_serial)
                    await self.writer.drain()
                    await self.ack.wait()

                    top = 0
                    end = top + w_size
                    while 1:
                        if end < len(message_serial):
                            frame_serial = message_serial[top:end]
                            self.writer.write(frame_serial)
                            await self.writer.drain()
                            top += w_size
                            end += w_size
                        else:
                            end = len(message_serial)
                            frame_serial = message_serial[top:end]
                            self.writer.write(frame_serial)
                            await self.writer.drain()
                            self.ack.clear()
                            break
                self.msg_queue.task_done()
        except Exception as err:
            logging.debug(err)

    async def handle_request(self, request):
        if self.login and self.username in self.server.server_blacklist:
            return {'status': 'fail', 'message': '用户已被封禁'}

        handlers = {
            'registration': self.registration_handler,
            'login': self.login_handler,
            'quit': self.quit_handler,
            'kick': self.kick_handler,
            'upload': self.upload_handler,
            'reset_pw': self.reset_pw_handler,
            'show_f': self.list_files_handler
        }
        handlers_async = {
            'download': self.download_handler,
            'broadcast': self.broadcast_handler
        }

        if request['header'] in handlers:
            handlers[request['header']](request)
        elif request['header'] in handlers_async:
            task = loop.create_task(handlers_async[request['header']](request))
            await task
        else:
            self.msg_queue.put_nowait(({'status': 'fail', 'message': '非法请求'}, 0))

    async def start_listen(self):
        try:
            while True:
                if self.pilot is not None:
                        temp = b""
                        n_frames = self.pilot[1]//self.pilot[0] + 1
                        for i in range(0, n_frames):
                            if i < n_frames-1:
                                frame = await self.reader.read(self.pilot[0])
                            else:
                                frame = await self.reader.read(self.pilot[1] - (n_frames-1)*self.pilot[0])
                            temp += frame
                        request = temp
                        self.pilot = None
                else:
                    request = await self.reader.read(512)
                request_data = extract_enc_data(self, request)

                if "header" in request_data:
                    task = loop.create_task(self.handle_request(request_data))
                elif "ack" in request_data:
                    self.ack.set()
                elif "pilot_data" in request_data:
                    self.pilot = request_data["pilot_data"]
                    ack = {'status': 'success', 'ack': 1}
                    self.msg_queue.put_nowait((ack, 0))
                elif "chunk_data" in request_data:
                    if request_data["chunk_data"] != "EOF":
                        chunk_bytes = b64decode(bytes(request_data["chunk_data"], encoding='utf-8'))
                        self.file_handler.write(chunk_bytes)
                    else:
                        self.file_handler.close()
                        self.msg_queue.put_nowait(({'from':"system", 'message': f"文件上传成功"}, 0))

        except Exception as e:
            self.server.logger.info(f'{self.username} 下线')


async def create_client_handler(reader, writer):
    client = Client_handler(reader, writer)
    client.server = server
    client.server.logger.info(f'与 {client.peername[0]}:{client.peername[1]} 建立链接')
    waiting_handshake = loop.create_task(client.respond_handshake())
    await waiting_handshake

    t2 = loop.create_task(client.sender())
    await asyncio.gather(client.start_listen())
    writer.close()


async def run_server(host, port):
    server1 = await asyncio.start_server(create_client_handler, host, port)
    await server1.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config_file', default="./server_config.json", help='服务器配置文件')
    args = parser.parse_args()

    server = Server(args.config_file)
    host = server.server_config['host']
    port = server.server_config['port']
    server.logger.info(f'服务器开启在 {host}:{port}')
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_server(host, port))


