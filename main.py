import ipaddress
import os
from flask import Flask, request, render_template, jsonify
import routeros_api

app = Flask(__name__)


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
        print(e)
        return 'Ошибка при выполнении действия: {}'.format(str(e))


# Маршрут для главной страницы
@app.route('/')
def home():
    return render_template('index.html')


# Маршрут для страницы API
@app.route('/api/action', methods=['GET'])
def api():
    # Получаем MAC-адрес из параметра запроса 'mac'
    mac_address = request.args.get('mac')

    # Получаем IP-адрес MikroTik из параметра запроса 'mikrotik_ip'
    # mikrotik_ip = str(ipaddress.IPv4Address(int(request.args.get('mikrotik_ip'))))
    mikrotik_ip = request.args.get('mikrotik_ip')
    print(mac_address, mikrotik_ip)
    return render_template('mktapi.html', mac_address=mac_address, mikrotik_ip=mikrotik_ip)


# Маршрут для обработки запроса продолжения
@app.route('/continue', methods=['POST'])
def continue_button():
    # Получаем MAC-адрес из формы
    mac_address = request.form.get('mac_address')
    print(mac_address)

    # Получаем IP-адрес MikroTik из формы
    mikrotik_ip = request.form.get('mikrotik_ip')
    print(mikrotik_ip)

    # Выполняем действия с использованием полученного MAC-адреса и IP-адреса MikroTik
    result = perform_action(mac_address, mikrotik_ip)

    return result


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, threaded=True)
