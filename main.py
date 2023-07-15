import os
import socket
import struct

import routeros_api
from flask import Flask, request, render_template, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+aiomysql://{os.getenv('SP_USER')}:{os.getenv('SP_PASSWD')}@{os.getenv('SP_HOST')}/radius"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
async_engine = create_async_engine(f"mysql+aiomysql://{os.getenv('SP_USER')}:{os.getenv('SP_PASSWD')}@{os.getenv('SP_HOST')}/radius")
async_session = sessionmaker(bind=async_engine, expire_on_commit=False, class_=AsyncSession)


class RadCheck(db.Model):
    __tablename__ = 'radcheck'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(64), nullable=False)
    attribute = db.Column(db.String(64), nullable=False)
    op = db.Column(db.String(2), nullable=False, default='==')
    value = db.Column(db.String(253), nullable=False)


# вот тут нужно расписать создание двух таблиц, userbillinfo и userinfo, для корректного отображения в daloradius
# class UserBillInfo(db.Model):
#     __tablename__ = 'userbillinfo'
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     username = db.Column(db.String(128), nullable=True)

def convert_ip(ip):
    converted_ip = socket.inet_ntoa(struct.pack('!L', int(ip)))
    return converted_ip


def perform_action(mac_addr, mikrotik_ip):
    mikrotik_host = os.environ.get('MIKROTIK_HOST')
    mikrotik_username = os.environ.get('MIKROTIK_USERNAME')
    mikrotik_password = os.environ.get('MIKROTIK_PASSWORD')

    if not all([mikrotik_host, mikrotik_username, mikrotik_password]):
        return 'Ошибка: Не заданы переменные среды для подключения к MikroTik'

    try:
        connection = routeros_api.RouterOsApiPool(host=mikrotik_host,
                                                  username=mikrotik_username,
                                                  password=mikrotik_password,
                                                  port=8728,
                                                  plaintext_login=True)
        api = connection.get_api()
        address_list = api.get_resource('ip/firewall/address-list')
        address_list.add(address=mikrotik_ip, list='authorized-users', timeout='02:00:00')
        connection.disconnect()
        return '+'
    except Exception as e:
        return 'Ошибка при выполнении действия: {}'.format(str(e))


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/hs', methods=['POST'])
def handle_form():
    mac = request.form.get('mac')
    ip = request.form.get('ip')
    username = request.form.get('username')
    link_login = request.form.get('link-login')
    link_login_only = request.form.get('link-login-only')
    link_orig = request.form.get('link-orig')
    error = request.form.get('error')

    print('mac:', mac)
    print('ip:', ip)
    print('username:', username)
    print('link-login:', link_login)
    print('link-login-only:', link_login_only)
    print('link-orig:', link_orig)
    print('error:', error)

    return render_template('auth.html',
                           mac=mac,
                           ip=ip,
                           username=username,
                           link_login=link_login,
                           link_login_only=link_login_only,
                           link_orig=link_orig,
                           error=error)


@app.route('/api/action-post', methods=['POST'])
async def api_post():
    mac_address = request.form.get('mac_address')
    ip_address = request.form.get('ip_address')
    username = request.form.get('username')
    link_login = request.form.get('link_login')
    link_login_only = request.form.get('link_login_only')
    link_orig = request.form.get('link_orig')
    error = request.form.get('error')

    async with async_session() as session:
        async with session.begin():
            radcheck_entry = RadCheck(username=mac_address, attribute='Cleartext-Password', op=':=', value='1')
            session.add(radcheck_entry)
            try:
                await session.flush()
            except:
                pass

            if radcheck_entry.id:
                try:
                    # Check if the async_session object is closed
                    if session.is_closed():
                        return
                    await session.close()
                except:
                    pass
                return jsonify({'success': True, 'redirect_url': link_login})
            else:
                return jsonify({'success': False})


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, threaded=True)
