#!/usr/bin/env python

import socket

class Facility:
    "Syslog facilities"
    KERN, USER, MAIL, DAEMON, AUTH, SYSLOG, LPR, NEWS, UUCP, CRON, AUTHPRIV, FTP = range(12)

    LOCAL0, LOCAL1, LOCAL2, LOCAL3, LOCAL4, LOCAL5, LOCAL6, LOCAL7 = range(16, 24)


class Level:
    "Syslog levels"
    EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG = range(8)


class Syslog:
    """
        A syslog client that logs to a remote server.
    """

    def __init__(self, host="localhost", port=514, facility=Facility.DAEMON):
        self.host = host
        self.port = port
        self.facility = facility
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, message, level_value):
        "Send a syslog message to remote host using UDP."
        data = "<%d>%s" % (level_value + (self.facility * 8), message)
        self.socket.sendto(data, (self.host, self.port))
