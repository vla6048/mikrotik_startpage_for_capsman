import ipaddress
import os
import socket
import struct
from flask import Flask, request, render_template, jsonify, make_response
import routeros_api

app = Flask(__name__)


def conver_ip(ip):
    print(ip)
    converted_ip = socket.inet_ntoa(struct.pack('!L', int(ip)))
    print(converted_ip)
    return converted_ip


def perform_action(mac_addr, mikrotik_ip):
    mikrotik_host = os.environ.get('MIKROTIK_HOST')
    mikrotik_username = os.environ.get('MIKROTIK_USERNAME')
    mikrotik_password = os.environ.get('MIKROTIK_PASSWORD')

    if not all([mikrotik_host, mikrotik_username, mikrotik_password]):
        return 'Ошибка: Не заданы переменные среды для подключения к MikroTik'

    try:
        print(mac_addr)
        print(mikrotik_ip)
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
        print(e)
        return 'Ошибка при выполнении действия: {}'.format(str(e))


# Маршрут для главной страницы
@app.route('/')
def home():
    return render_template('index.html')


# Маршрут для страницы API
@app.route('/api/action-get', methods=['GET'])
def api_get():
    mac_address = request.args.get('mac')
    mikrotik_ip_str = request.args.get('mikrotik_ip')
    mikrotik_ip = mikrotik_ip_str
    print(mac_address, mikrotik_ip)
    return render_template('mktapi.html', mac_address=mac_address, mikrotik_ip=mikrotik_ip)


@app.route('/api/action-post', methods=['POST'])
def api_post():
    mac_address = request.form.get('mac_address')
    mikrotik_ip_numeric = request.form.get('mikrotik_ip')
    mikrotik_ip = conver_ip(mikrotik_ip_numeric)

    result = perform_action(mac_address, mikrotik_ip)

    if result == '+':
        return render_template('finish.html')
    else:
        return result


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, threaded=True)
