import sqlite3
import sys
sys.path.append("..")
from misc.encryption_misc import get_sha256


class db_connection:
    def __init__(self, server_config):
        self.server_config = server_config
        self.conn = sqlite3.connect(server_config["db_path"])
        self.db_init()

    def db_init(self):
        c = self.conn.cursor()
        c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='USERS' ''')

        result = c.fetchone()
        if result[0] == 0:
            c.execute('''CREATE TABLE USERS
                                  (UID INTEGER PRIMARY KEY  AUTOINCREMENT,
                                  USERNAME     TEXT UNIQUE,
                                  PASSWORD_HASH  TEXT,
                                  ROLE TEXT );''')

            c.execute('''INSERT INTO USERS(USERNAME,PASSWORD_HASH,ROLE) VALUES(?,?,?);''',
                      [self.server_config["default_admin_username"],
                       get_sha256(self.server_config["default_admin_password"]),
                       "administrator"])

            self.conn.commit()
            pass

    def reset_password(self, username, new_password):
        new_password_hash = get_sha256(new_password)
        update_query_pre = '''UPDATE USERS SET PASSWORD_HASH=? WHERE USERNAME=?;'''
        c = self.conn.cursor()
        try:
            c.execute(update_query_pre, [new_password_hash, username])
            self.conn.commit()
        except sqlite3.Error as err:
            return {'status': 'fail', 'message': str(err)}
        return {'status': 'success', 'message': '修改密码成功'}

    def verify_login(self, username, password):
        password_hash = get_sha256(password)
        c = self.conn.cursor()
        c.execute('SELECT PASSWORD_HASH FROM USERS WHERE USERNAME=?', [username])
        row = c.fetchone()
        if row is None:
            return False
        if row[0] == password_hash:
            return True
        else:
            return False

    def confirm_registration(self, username, password):
        password_hash = get_sha256(password)
        role = "user"
        c = self.conn.cursor()
        try:
            insert_query_pre = '''INSERT INTO USERS(USERNAME,PASSWORD_HASH,ROLE) VALUES(?,?,?);'''
            c.execute(insert_query_pre, [username, password_hash, role])
            self.conn.commit()
            return {'status': 'success', 'message': '注册成功'}
        except sqlite3.Error as err:
            if err.__class__ == sqlite3.IntegrityError:
                return {'status': 'fail', 'message': '用户名已存在'}
            else:
                return {'status': 'fail', 'message': 'unknown'}

    def get_role(self, username):
        c = self.conn.cursor()
        c.execute('SELECT ROLE FROM USERS WHERE USERNAME=?', [username])
        row = c.fetchone()
        return row[0]
