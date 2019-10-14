#!/usr/bin/env python


from st2reactor.sensor.base import Sensor
import socket


class SyslogSensor(Sensor):
    """Syslog Sensor"""

    def __init__(self, sensor_service, config=None):
        super(SyslogSensor, self).__init__(sensor_service=sensor_service, config=config)
        self._logger = self.sensor_service.get_logger(name=self.__class__.__name__)
        self._sensor_listen_ip = '0.0.0.0'

        # Get socket.error: [Errno 13] Permission denied when binding with port 514
        # In unix (Linux, Ubuntu etc) systems, ports less than 1024 can not be bound to by normal users, 
        # only the root user can bind to those ports.
        # Solution is forware 514 package to 8514
        self._sensor_listen_port = 8514
        self._trigger = 'xmc.syslog_event'
        self._run = True
        self._logger.info("[SyslogSensor] Init ")

    def setup(self):
        pass

    def run(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._server.bind((self._sensor_listen_ip, self._sensor_listen_port))
        self._logger.info("[SyslogSensor] is running with port 8514")
        while self._run:
            message, host = self._server.recvfrom(2048)
            payload = dict()
            payload['host'] = str(host)
            payload['message'] = str(message)

            self._logger.info("[SyslogSensor]  message from: " + str(host))
            self._logger.info("[SyslogSensor]  message: " + str(message))
            self._sensor_service.dispatch(trigger=self._trigger, payload=payload)

        self._server.close()

    def cleanup(self):
        self._run = False

    def add_trigger(self, trigger):
        """Stuff."""
        pass

    def update_trigger(self, trigger):
        """Stuff."""
        pass

    def remove_trigger(self, trigger):
        """Stuff."""
        pass
