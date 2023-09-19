"""
@File : demo.py
@Author : Dustin Wei
@Email : dustin.wei@quectel.com
@Date : 2023/9/19 10:15 
"""

import ujson
from usr.onenetIot import OneNetIot


if __name__ == '__main__':
    cloud_config = {
        "product_id": "pKYswKsPeR",
        "port": 1883,
        "server": "mqtts.heclouds.com",
        "device_id": "device1",
        "access_key": "H2mZK/3XW5Uv/cnN7fEf8TnFG3WTu3V1a6eZpe/1J0s=",
        "keepalive": 60,
        "qos": 0,
        "subscribe": {
            "1": "$sys/pKYswKsPeR/device1/dp/post/json/rejected",
            "0": "$sys/pKYswKsPeR/device1/dp/post/json/accepted"
        },
        "publish": {
            "0": "$sys/pKYswKsPeR/device1/dp/post/json"
        }
    }

    cloud = OneNetIot(
        cloud_config['product_id'],
        cloud_config['device_id'],
        cloud_config['access_key'],
        server=cloud_config['server'],
        port=cloud_config['port'],
        qos=cloud_config['qos'],
        subscribe=cloud_config['subscribe'],
        publish=cloud_config['publish'],
    )

    if cloud.init(enforce=True):
        print('cloud init successfully.')
        res = cloud.post_data(
            '0',
            ujson.dumps({"id": 1,"dp": {"data": [{"v": 500}]}})
        )
        print('test post result: {}'.format(res))
    else:
        print('cloud init failed.')
