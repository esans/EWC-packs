#!/usr/bin/env python


from st2actions.runners.pythonrunner import Action

from Syslog_client_utils import Facility
from Syslog_client_utils import Level
from Syslog_client_utils import Syslog

class SyslogClient(Action):
    def run(self, host=None, level=None, message=None):
        retval = True

        log = Syslog(host)

        if level == "Emergency":
            level_value = Level.EMERG
        elif level == "Alert":
            level_value = Level.ALERT
        elif level == "Critical":
            level_value = Level.CRIT
        elif level == "Error":
            level_value = Level.ERR
        elif level == "Warning":
            level_value = Level.WARNING
        elif level == "Notice":
            level_value = Level.NOTICE
        elif level == "Informational":
            level_value = Level.INFO
        elif level == "Debug":
            level_value = Level.DEBUG
        else:
            retval = False

        log.send(message, level_value)

        return retval

