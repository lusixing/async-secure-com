import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes


def aes_gcm_encrypt(iv, key, plaintext):
    encryptor = Cipher(algorithms.AES(key),modes.GCM(iv),).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (ciphertext, encryptor.tag)


def aes_gcm_decrypt(key, iv, ciphertext, tag):
    decryptor = Cipher(algorithms.AES(key),modes.GCM(iv, tag),).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def get_sha256(s):
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(bytes(s, encoding='utf-8'))
    s_hash = digest.finalize()
    return s_hash


def serialize_data(data):
    data = json.dumps(data).encode('utf-8')
    return data


def extract_data(data):
    return json.loads(data.decode('utf-8'))


def extract_enc_data(obj, data_enc):
    if type(data_enc) != dict:
        if type(data_enc) == bytes:
            msg = json.loads(data_enc.decode('utf-8'))
        else:
            msg = json.loads(data_enc)
    else:
        msg = data_enc
    if 'payload' in msg:
        payload_enc = b64decode(bytes(msg["payload"], encoding='utf-8'))
        tag = b64decode(bytes(msg["tag"], encoding='utf-8'))
        payload = json.loads(aes_gcm_decrypt(obj.share_key, obj.iv, payload_enc, tag))
        return payload
    else:
        return msg


def serialize_enc_data(obj, payload):
    payload_enc, tag = aes_gcm_encrypt(obj.iv, obj.share_key, bytes(json.dumps(payload), encoding="utf8"))
    message_json = {"tag": str(b64encode(tag), encoding="utf8"),
                    "payload": str(b64encode(payload_enc), encoding="utf8")}
    message = json.dumps(message_json)
    return message


def serialize_enc_byte_data(obj, byte_chunk):
    payload_enc, tag = aes_gcm_encrypt(obj.iv, obj.share_key, byte_chunk)
    message_json = {"tag": str(b64encode(tag), encoding="utf8"),
                    "payload": str(b64encode(payload_enc), encoding="utf8")}
    message = json.dumps(message_json)
    return message


def extract_enc_byte_data(obj, message_serial):
    message = json.loads(message_serial)
    chunk_enc = b64decode(bytes(message["chunk_enc"], encoding='utf-8'))
    tag = b64decode(bytes(message["tag"], encoding='utf-8'))
    chunk_dec = aes_gcm_decrypt(obj.share_key, obj.iv, chunk_enc, tag)
    return chunk_dec
