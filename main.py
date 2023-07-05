import os
import socket
import struct
from flask import Flask, request, render_template, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import routeros_api

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{os.getenv('SP_USER')}:{os.getenv('SP_PASSWD')}@{os.getenv('SP_HOST')}/radius"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


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
#


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
        arp_list = api.get_resource('caps-man/access-list')
        arp_list.add(comment=mikrotik_ip, mac_address=mac_addr)
        connection.disconnect()
        return '+'
    except Exception as e:
        return 'Ошибка при выполнении действия: {}'.format(str(e))


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/api/action-get', methods=['GET'])
def api_get():
    mac_address = request.args.get('mac')
    mikrotik_ip_str = request.args.get('mikrotik_ip')
    mikrotik_ip = mikrotik_ip_str
    return render_template('mktapi.html', mac_address=mac_address, mikrotik_ip=mikrotik_ip)


@app.route('/api/action-post', methods=['POST'])
def api_post():
    mac_address = request.form.get('mac_address')
    mikrotik_ip_numeric = request.form.get('mikrotik_ip')
    mikrotik_ip = convert_ip(mikrotik_ip_numeric)

    result = perform_action(mac_address, mikrotik_ip)

    if result == '+':
        # Добавление записи в таблицу radcheck
        radcheck_entry = RadCheck(username=mac_address, attribute='Cleartext-Password', op=':=', value='1')
        db.session.add(radcheck_entry)
        db.session.commit()

        return render_template('finish.html')
    else:
        return result


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, threaded=True)
