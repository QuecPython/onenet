import utime
from umqtt import MQTTClient
from usr.utils import new as hmac_new, sha256, b64encode, b64decode, Thread


_URL_CONVERT_MAP = {
    '+': '%2B',
    ' ': '%20',
    '/': '%2F',
    '?': '%3F',
    '%': '%25',
    '#': '%23',
    '&': '%26',
    '=': '%3D'
}


def urlencode(string):
    rv = ''
    for char in string:
        rv += _URL_CONVERT_MAP.get(char,  char)
    return rv


class OneNetIot(object):

    OTA_INFORM = '$sys/{}/{}/ota/inform'
    OTA_INFORM_REPLY = '$sys/{}/{}/ota/inform_reply'

    def __init__(
            self,
            product_id,
            device_id,
            access_key,
            version='2018-10-31',
            server='mqtts.heclouds.com',
            port=1883,
            **kwargs
    ):
        super().__init__()
        self.__product_id = product_id
        self.__device_id = device_id
        self.__server = server
        self.__port = port
        self.__version = version
        self.__access_key = access_key
        self.__kwargs = kwargs

        self.__mqtt = None
        self.__listen_thread = Thread(target=self.__listen)
        self.__callback = None

    def set_callback(self, cb):
        if not callable(cb):
            raise TypeError
        self.__callback = cb

    def init(self, enforce=False):

        print("init onenet cloud enforce: {}".format(enforce))
        if enforce is False and self.__mqtt is not None:
            if self.get_status():
                print('onenet cloud status ok.')
                return True

        if self.__mqtt is not None:
            self.close()

        token = self.__generate_token()
        self.__mqtt = MQTTClient(
            self.__device_id,
            self.__server,
            port=self.__port,
            user=self.__product_id,
            password=token,
            reconn=False,
            keepalive=self.__kwargs.get('keepalive', 60)
        )
        self.__mqtt.set_callback(self.__recv_callback)

        try:
            self.__mqtt.connect(clean_session=self.__kwargs.get('clean_session', True))
        except Exception as e:
            print('connect error: {}'.format(e))
            return False

        try:
            self.__subscribe()
        except Exception as e:
            print('prepare subscribe/publish topic error: {}'.format(e))
            self.close()
            return False

        self.__listen_thread.start()
        return True

    def __generate_token(self):
        # res = 'products/{}'.format(ProductId)  # 一型一密
        res = 'products/{}/devices/{}'.format(self.__product_id, self.__device_id)  # 一机一密
        et = utime.mktime(utime.localtime()) + 365 * 24 * 60 * 60  # 一年有效期
        method = 'sha256'
        message = '\n'.join([str(et), method, res, self.__version])
        hash_obj = hmac_new(
            b64decode(self.__access_key),
            message.encode(),
            digestmod=sha256
        )
        sign = b64encode(hash_obj.digest()).decode()
        token = 'version={}&res={}&et={}&method={}&sign={}'.format(
            urlencode(self.__version), urlencode(res), urlencode(str(et)), urlencode(method), urlencode(sign)
        )
        return token

    def __recv_callback(self, topic, data):
        topic = topic.decode()
        print('topic: {}; data: {}'.format(topic, data))
        if self.__callback is not None:
            self.__callback(topic, data)

    def __subscribe(self):
        qos = self.__kwargs.get('qos', 0)
        for topic in self.__kwargs.get('subscribe', {}).values():
            self.__mqtt.subscribe(topic, qos)

    def __listen(self):
        while True:
            try:
                self.__mqtt.wait_msg()
                utime.sleep_ms(20)
            except Exception as e:
                print('wait message error: {}'.format(e))
                break

    def get_status(self):
        return self.__mqtt.get_mqttsta() == 0 if self.__mqtt is not None else False

    def close(self):
        """Cloud disconnect"""
        self.__mqtt.disconnect()
        self.__listen_thread.stop()

    def post_data(self, topic_id, data):
        """发布消息"""
        publish_topics = self.__kwargs.get('publish')
        if publish_topics is None:
            print('publish topics is None.')
            return False

        topic = publish_topics.get(topic_id)
        if topic is None:
            print('can not get publish topic by topic id: {}'.format(topic))
            return False

        try:
            self.__mqtt.publish(topic, data, retain=False, qos=self.__kwargs.get('qos', 0))
        except Exception as e:
            print('onenet mqtt through post data failed: {}'.format(e))
            return False

        return True
