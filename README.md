# OneNet demo

本文档简单演示onenet接入，和订阅发布。

##### 1、导入OneNet云对象类。
```python
from usr.onenetIot import OneNetIot
```

##### 2、实例参数
```python
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
```

##### 3、实例化云对象
```python
from usr.onenetIot import OneNetIot
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

# 自定义订阅主题回调函数
def subscribe_callback(topic, data):
    print('get topic: {}, data: {}'.format(topic, data))
# 设置下行订阅主题的回调函数
cloud.set_callback(subscribe_callback)
    
# 对象初始化，此方法中会连接onenet云服务（mqtt通道），并订阅参数中`subscribe`设置的主题。
cloud.init(enforce=True)
```

##### 4、发布消息
```python
# 注意：onenet发布主题消息有一定格式，具体格式参考onenet官方的主题格式
res = cloud.post_data(
        '0',  # 自定义主题id
        ujson.dumps({"id": 1,"dp": {"data": [{"v": 500}]}})
    )
print('test post result: {}'.format(res))
```


##### 5、订阅主题回调函数
`OneNetIot.__recv_callback`默认是主题回调函数，当有下行主题消息时，该函数会被回调，用户可重写该函数实现主题消息的处理。