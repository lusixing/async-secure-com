import sys
sys.path.append("..")

import asyncio
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from misc.encryption_misc import *

from contextlib import suppress
from asynccmd import Cmd
import logging
import json
import os
import argparse

logging.basicConfig(level=logging.INFO, format='%(message)s')


def extract_data(data):
    return json.loads(data.decode('utf-8'))


def display(payload):
    if "message" in payload:
        message = payload["message"]
        if "from" in payload:
            msg_source = payload["from"]
        else:
            msg_source = "system"
        logging.info("[{}]{}".format(msg_source, message))


def gen_random_iv(length):
    return os.urandom(length).decode('unicode_escape').encode('utf-8')


async def connect(host, port):
    reader, writer = await asyncio.open_connection(host, int(port))
    return reader, writer


class Client_cli(Cmd):
    def __init__(self, client_configs, intro, prompt="not login>> "):
        super().__init__(mode=mode)
        self.intro = intro
        self.prompt = prompt
        self.loop = None
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.share_key = None
        self.iv = gen_random_iv(12)
        self.writer = None
        self.reader = None
        self.pilot = None
        self.ack = asyncio.Event()
        self.reply = asyncio.Queue()
        self.incoming_size = None
        self.received_size = 0
        self.client_configs = client_configs
        self.file_handler = None

    async def handshake(self):
        serialized_public_key1 = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                              format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        message_json = {"header": "handshake", "public_key": serialized_public_key1, "iv": str(self.iv, encoding="utf8")}
        message = json.dumps(message_json)
        self.writer.write(message.encode())
        await self.writer.drain()

        data = await self.reader.read(512)
        res = extract_data(data)
        if res['success']:
            server_public_key_serial = bytes(res['server_public_key'], encoding="utf8")
            server_public_key = serialization.load_pem_public_key(server_public_key_serial)
            self.share_key = self.private_key.exchange(server_public_key)
            logging.info("handshake successful")

    async def listener(self):
        while True:
            if self.share_key is None:
                data = await self.reader.read(512)
                data = extract_data(data)
            else:
                if self.pilot is not None:
                    temp = b""
                    n_frames = self.pilot[1] // self.pilot[0] + 1
                    for i in range(0, n_frames):
                        if i < n_frames - 1:
                            frame = await self.reader.read(self.pilot[0])
                        else:
                            frame = await self.reader.read(self.pilot[1] - (n_frames - 1) * self.pilot[0])
                        temp += frame
                    self.pilot = None
                    data = temp
                else:
                    data = await self.reader.read(512)

                data = extract_enc_data(self, data)
                if "header" in data and data["header"] == "pilot":
                    self.pilot = data["pilot_data"]
                    ack = {"ack": 1}
                    ack_enc = serialize_enc_data(self, ack)
                    self.writer.write(bytes(ack_enc, encoding='utf-8'))
                    await self.writer.drain()
                elif "allow_ul" in data:
                    self.reply.put_nowait(data["allow_ul"])
                elif "allow_dl" in data:
                    self.reply.put_nowait(data["allow_dl"])
                    self.incoming_size = data["fsize"]
                elif "chunk_data" in data:
                    if data["chunk_data"] != "EOF":
                        chunk_bytes = b64decode(bytes(data["chunk_data"], encoding='utf-8'))
                        self.file_handler.write(chunk_bytes)
                        self.received_size += len(chunk_bytes)
                        progress = 100 * self.received_size / self.incoming_size
                        logging.info(f"下载进度：{round(progress, 2)}%")
                    else:
                        self.file_handler.close()
                        logging.info(f"下载成功")

            logging.debug(f'Received: {data!r}')
            if "ack" in data:
                self.ack.set()
            display(data)

    async def forward_data(self, message):
        w_size = 128
        message_serial = bytes(message, encoding='utf-8')
        pilot_data = (w_size, len(message_serial))

        pilot_payload = {"pilot_data": pilot_data}
        pilot_message = serialize_enc_data(self, payload=pilot_payload)
        self.writer.write(pilot_message.encode())
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
                break
        self.ack.clear()

    async def registration(self, *args):
        username, password = args[0].split()
        payload = {"header": "registration", "username": str(username), "password": str(password)}
        message = serialize_enc_data(self, payload=payload)

        logging.debug(f'Send: {message!r}')
        self.writer.write(message.encode())
        await self.writer.drain()

    async def login(self, *args):
        username, password = args[0].split()
        payload = {"header": "login", "username": str(username), "password": str(password)}
        message = serialize_enc_data(self, payload=payload)

        logging.debug(f'Send: {message!r}')
        self.writer.write(message.encode())
        await self.writer.drain()
        self.prompt = username + ">> "

    async def send(self, msg):
        payload = {"header": "broadcast", "message": str(msg)}
        message = serialize_enc_data(self, payload=payload)

        logging.debug(f'Send: {payload!r}')
        self.loop.create_task(self.forward_data(message))

    async def download_file(self, fname):
        if not os.path.exists(self.client_configs["file_folder"]):
            os.mkdir(self.client_configs["file_folder"])
        fpath = os.path.join(self.client_configs["file_folder"], fname)
        self.file_handler = open(fpath, 'ab')

        payload = {"header": "download", "fname": str(fname)}
        message = serialize_enc_data(self, payload=payload)

        logging.debug(f'Send: {payload!r}')
        task = self.loop.create_task(self.forward_data(message))
        await task
        reply = await self.reply.get()
        if reply == "n":
            logging.info(f'服务器拒绝下载')
            self.file_handler.close()
        elif reply == "y":
            self.received_size = 0
            logging.info(f'开始下载')

    async def send_file(self, fname):
        if os.path.isfile(fname):
            temp = fname
            fname = os.path.basename(fname)
            fpath = temp
        else:
            fpath = os.path.join('./files', fname)
        if not os.path.exists(fpath):
            logging.info(f'文件不存在')
            return

        fsize = os.path.getsize(fpath)
        payload = {"header": "upload", "fname": str(fname), "fsize": fsize}
        message = serialize_enc_data(self, payload=payload)

        logging.debug(f'Send: {payload!r}')
        task = self.loop.create_task(self.forward_data(message))
        await task
        reply = await self.reply.get()
        if reply == "n":
            logging.info(f'服务器拒绝上传')
        elif reply == "y":
            chunk_size = 8192
            file_handle = open(fpath, 'rb')
            sent_bytes = 0
            while True:
                chunk = file_handle.read(chunk_size)
                if not chunk:
                    break
                payload = {"chunk_data": str(b64encode(chunk), encoding='utf-8')}
                message = serialize_enc_data(self, payload=payload)

                task = self.loop.create_task(self.forward_data(message))
                await task
                sent_bytes += chunk_size
                progress = 100 * sent_bytes/fsize
                logging.info(f"上传进度：{round(progress,2)}%")
            EOF = serialize_enc_data(self, {"chunk_data": "EOF"})
            self.loop.create_task(self.forward_data(EOF))
            file_handle.close()
            logging.info(f"上传完成")

    async def show_server_files(self):
        payload = {"header": "show_f"}
        message = serialize_enc_data(self, payload=payload)

        logging.debug(f'Send: {payload!r}')
        self.loop.create_task(self.forward_data(message))

    async def reset_pw(self, new_pw):
        payload = {"header": "reset_pw", "new_password": new_pw}
        message = serialize_enc_data(self, payload=payload)

        logging.debug(f'Send: {payload!r}')
        self.loop.create_task(self.forward_data(message))

    async def kick_user(self, username):
        payload = {"header": "kick", "username": str(username)}
        message = serialize_enc_data(self, payload=payload)
        logging.debug(f'Send: {message!r}')
        self.writer.write(message.encode())
        await self.writer.drain()

    async def quit_client(self):
        payload = {"header": "quit"}
        message = serialize_enc_data(self, payload=payload)
        logging.debug(f'Send: {message!r}')
        t = self.loop.create_task(self.forward_data(message))
        await t
        logging.info(f"退出客户端")

        self.writer.close()
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        [task.cancel() for task in tasks]
        self.loop.stop()

    def do_login(self, *args):
        self.loop.create_task(self.login(*args))

    def do_reg(self, *args):
        self.loop.create_task(self.registration(*args))

    def do_resetpw(self, new_pw):
        self.loop.create_task(self.reset_pw(new_pw))

    def do_send(self, msg):
        self.loop.create_task(self.send(msg))

    def do_kick(self, username):
        self.loop.create_task(self.kick_user(username))

    def do_ul(self, fname):
        self.loop.create_task(self.send_file(fname))

    def do_dl(self, fname):
        self.loop.create_task(self.download_file(fname))

    def do_sf(self, arg):
        self.loop.create_task(self.show_server_files())

    def do_quit(self, arg):
        self.loop.create_task(self.quit_client())


    def start(self, loop=None, reader=None, writer=None):
        self.loop = loop
        self.reader = reader
        self.writer = writer

        task = self.loop.create_task(self.handshake())
        self.loop.run_until_complete(task)

        self.loop.create_task(self.listener())
        super().cmdloop(loop)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config_file', default="./client_config.json", help='客户端配置文件')
    args = parser.parse_args()

    configs = json.loads(open(args.config_file, 'r').read())
    loop = asyncio.get_event_loop()
    mode = "Run"

    task = asyncio.ensure_future(connect(configs["host"], configs["port"]))
    loop.run_until_complete(task)
    reader, writer = task.result()

    cmd = Client_cli(client_configs=configs ,intro="启动客户端")
    cmd.start(loop, reader, writer)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.stop()
        pending = asyncio.Task.all_tasks(loop=loop)
        for task in pending:
            task.cancel()
            with suppress(asyncio.CancelledError):
                loop.run_until_complete(task)
        loop.close()


