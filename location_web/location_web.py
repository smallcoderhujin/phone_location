#!/usr/bin/python3
# coding=utf-8
import json
import os

from flask import Flask, render_template, request, redirect, jsonify

app = Flask('location_web')

USERNAME = 'admin'
PWD = '88888888'
KEY_USER = '186xxxxxxxx'
PROJECT_PATH = os.path.dirname(__file__)

LOCATION_DATA_DIR = os.environ.get('LOCATION_DATA_DIR', "/etc/location")
XIAOMI_LOCATION_DATA_PATH = '%s/xiaomi' % LOCATION_DATA_DIR
HUAWEI_LOCATION_DATA_PATH = '%s/huawei' % LOCATION_DATA_DIR
REALME_LOCATION_DATA_PATH = '%s/realme' % LOCATION_DATA_DIR
LOGIN = False


def get_data(data_dir):
    data = []
    if os.path.exists(data_dir):
        for fl_name in os.listdir(data_dir):
            fl_path = '%s/%s' % (data_dir, fl_name)
            with open(fl_path) as fl:
                device_info = json.loads(fl.read())
                if fl_name == KEY_USER:
                    is_key = True
                else:
                    is_key = False
                d = {'title': device_info['location']['name'],
                     'point': '%s,%s' % (device_info['location']['longitude'], device_info['location']['latitude']),
                     'tel': fl_name,
                     'is_key': is_key,
                     'time': device_info['datetime'],
                     'longitude': device_info['location']['longitude'],
                     'latitude': device_info['location']['latitude']}
                data.append(d)
    return data


def format_data():
    # { title: "名称：广州火车站", point: "113.264531,23.157003", address: "广东省广州市广州火车站", tel: "12306" },

    xiao_devices = get_data(XIAOMI_LOCATION_DATA_PATH)
    huawei_devices = get_data(HUAWEI_LOCATION_DATA_PATH)
    realme_devices = get_data(REALME_LOCATION_DATA_PATH)
    print('xiaomi location', xiao_devices)
    print('huawei location', huawei_devices)
    print('realme location', realme_devices)
    return xiao_devices + huawei_devices + realme_devices


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.route('/get_location', methods=['GET'])
def get_location():
    try:
        data = format_data()
        print('get_location', data)
        return jsonify({'locations': data})
    except Exception as ex:
        return jsonify({'error': ex})


@app.route('/', methods=['GET'])
def index():
    global LOGIN
    if LOGIN:
        return render_template('index.html')
    return redirect("/login")


@app.route('/login', methods=['GET'])
def login_web():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    remote_addr = request.remote_addr
    print('Remote user %s try login.' % remote_addr)

    name = request.form.get('username')
    pwd = request.form.get('password')
    if pwd == PWD and name == USERNAME:
        print('Remote user %s login success.' % remote_addr)
        global LOGIN
        LOGIN = True
        return redirect('/')
    print('Remote user %s login failed.' % remote_addr)
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
