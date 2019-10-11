#!/usr/bin/env python


from st2actions.runners.pythonrunner import Action


class ParseString(Action):
    def run(self, message=None, key=None):
        # <Erro:POE.port_fault> Slot-1: Port 1:19 has encountered a fault condition
        port_number = ''
        strlist = message.split()
        index = 0
        found = False
        for word in strlist:
            if word == key:
                found = True
                break
            index = index + 1

        if found:
            word = strlist[index + 1]

            port_list = word.split(":")
            port_number = port_list[1]

        return (found, {"port":port_number})
