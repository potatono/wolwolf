#!/usr/bin/env python3

import re
import os
import sys
import socket
from multiprocessing.pool import ThreadPool
import struct
import argparse
import configparser
import socketserver
from threading import Thread
from time import sleep
import json
import logging

PORT = 19653
WOL_PORT = 9
BROADCAST = "255.255.255.255"

ALLOW = { '127.0.0.1': True }

CMDS = {
    'shutdown': {
        'darwin': 'sudo shutdown -h now',
        'win32': 'shutdown -t 0 -s'
    },
    'sleep': {
        'darwin': 'pmset sleepnow',
        'win32': 'rundll32.exe powrprof.dll, SetSuspendState Sleep'
    },
    'wake': {
        'darwin': 'caffeinate -u -t 1'
    },
    'restart': {
        'win32': 'shutdown -t 0 -r',
        'darwin': 'sudo shutdown -r now'
    }
}

class Config:
    def __init__(self):
        self.parse_args()
        self.parse_config()
    
    def parse_args(self):
        parser = argparse.ArgumentParser(description="WOL tools and daemon for additional functions")
        parser.add_argument('-d', dest='daemon', action='store_const', const=True, default=False, help='Run server daemon')
        parser.add_argument('-f', dest='config_path', nargs='?', default=None, help='Path to config file')
        parser.add_argument('-l', dest='log_path', nargs='?', default=None, help='Path to log file')
        parser.add_argument('-w', dest='wake', nargs='+', default=None, help='Wake host(s)')
        parser.add_argument('-s', dest='sleep', nargs='+', default=None, help='Sleep host(s)')
        parser.add_argument('-S', dest='shutdown', nargs='+', default=None, help='Shutdown host(s)')
        parser.add_argument('-r', dest='reboot', nargs='+', default=None, help='Reboot host(s)')
        parser.add_argument('-i', dest='interactive', action='store_const', const=True, default=False, help='Interactive mode')
        self.args = parser.parse_args()

    def find_config(self):
        if self.args.config_path:
            return self.args.config_path
        
        locations = [
            os.getenv('WOLWOLF_CONFIG', default=None),
            '/etc/wolwolf.conf', '~/.wolwolf.conf', '~/.config/wolwolf.conf', 'wolwolf.conf'
        ]

        for location in locations:
            if location is not None and os.path.exists(location):
                return location
        
        return None
    
    def parse_config(self):
        config_path = self.find_config()
        self.file = configparser.ConfigParser()

        if config_path is None:
            return
        
        self.file.read(config_path)

def Logger(config):
    logger = logging.getLogger()
    logger.setLevel(config.file.get("DEFAULT", "log_level", fallback="INFO"))

    formatter = logging.Formatter("[%(asctime)s %(levelname)5s] %(message)s")

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    log_path = config.file.get("DEFAULT", "log_path_{}".format(sys.platform), 
                          fallback=config.file.get("DEFAULT", "log_path", fallback=None))
    
    if log_path:
        handler = logging.FileHandler(log_path)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

class WolwolfServerHandler(socketserver.BaseRequestHandler):
    thread = None

    def run(self, cmdline):
        sleep(1)
        self.server.logger.info("Running '{}'".format(cmdline))
        os.system(cmdline)

    def handle(self):
        cmd = str(self.request.recv(1024).strip(), encoding='utf8')
        source = self.client_address[0]
        self.server.logger.info("Received {} from {}".format(cmd,source))

        if cmd == 'ping':
            self.request.sendall(b"PONG\n")
            return
        
        if source not in ALLOW:
            self.server.logger.info("{} not allowed".format(source))
            self.request.sendall(b"ERROR\n")
            return

        if cmd not in CMDS:
            self.server.logger.info("{} not a command".format(cmd))
            self.request.sendall(b"ERROR\n")
            return

        if sys.platform not in CMDS[cmd]:
            self.server.logger.info("{} not supported".format(sys.platform))
            self.request.sendall(b"ERROR\n")
            return

        # Clean up thread from previous call to handle
        if self.thread:
            self.thread.join()

        cmdline = CMDS[cmd][sys.platform]
        self.thread = Thread(target=self.run, args=(cmdline, ))
        self.thread.start()

        self.request.sendall(b"OK\n")

class WolwolfServer:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def import_allowed_hosts(self):
        hosts = json.loads(self.config.file.get("DEFAULT", "allowed_hosts"))
        for host in hosts:
            ALLOW[host] = True

    def run(self):
        self.import_allowed_hosts()
        with socketserver.TCPServer(("0.0.0.0", PORT), WolwolfServerHandler) as server:
            self.logger.info("Listening on {}".format(PORT))
            server.config = self.config
            server.logger = self.logger
            server.serve_forever()

class WolwolfClient:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.hosts_path = self.find_hosts()
        self.hosts = self.read_hosts(self.hosts_path)

    def run(self):
        if self.config.args.wake:
            self.wake_hosts()
        
        if self.config.args.sleep:
            self.sleep_hosts()
        
        if self.config.args.shutdown:
            self.shutdown_hosts()

        if self.config.args.reboot:
            self.reboot_hosts()

        self.ping_hosts()
        self.print_hosts()

    def find_hosts(self):
        locations = [ 
            os.getenv('WOLWOLF_HOSTS', default=None),
            '/etc/wakeable-hosts', '~/.wakeable-hosts', '~/.config/wakeable-hosts', 'wakeable-hosts'
        ]

        for location in locations:
            if location is not None and os.path.exists(location):
                return location
        
        return None

    def read_hosts(self, path):
        hosts = []

        with open(path, "r") as fil:
            for line in fil:
                line = re.sub("#.*","",line).strip()

                if not line:
                    next

                (ip, hwaddr, hostname) = re.split("\\s+", line)

                if ip and hwaddr and hostname:
                    hosts.append({ "ip": ip, "hwaddr": hwaddr, "hostname": hostname })
                else:
                    self.logger.error(f"Invalid line: {line}")

        return hosts

    def cmd(self, ip, cmd):
        try:
            self.logger.info(f"Sending {cmd} to {ip}")
            socket.setdefaulttimeout(1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, PORT))
            s.sendall(bytes(cmd + "\n", encoding='utf-8'))
            resp = s.recv(10)
        except OSError as error:
            return None
        else:
            s.close()
            return str(resp, encoding='utf-8').strip()

    def ping(self, ip):
        return self.cmd(ip, "ping")

    def ping_host(self, host):
        result = self.ping(host['ip'])
        host['isup'] = result is not None
        self.logger.info(f"{host['ip']} is {host['isup']}.")
        return result

    def ping_hosts(self):
        self.logger.info("Starting pool")
        tp = ThreadPool()
        tp.map(self.ping_host, self.hosts)

    def print_hosts(self):
        for host in self.hosts:
            print(f"{host['hostname']:20}\t{host['ip']:15}\t{host['hwaddr']:20}\t{host['isup'] and 'UP' or 'DOWN'}")

    def wake(self, hwaddr):
        self.logger.info(f"Sending WOL for {hwaddr} to {BROADCAST}..")

        # Magic packet is FF x 6 plus MAC x 16
        s = "F" * 12 + hwaddr.replace(":","") * 16
        packet = bytes.fromhex(s)

        soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        soc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
        soc.sendto(packet, (BROADCAST, WOL_PORT))
        soc.close()

    def get_host(self, h):
        for host in self.hosts:
            if (host['hostname'] == h or
                host['ip'] == h or
                host['hwaddr'] == h):
                    return host

        return None

    def wake_host(self, host):
        for i in range(5):
            self.wake(host['hwaddr'])
            sleep(i+1)
            result = self.cmd(host['ip'], 'wake')

            if result:
                return result
            
            self.logger.info(f"No response.  Will try again.  {i+1}/5")

    def wake_hosts(self):
        for h in self.config.args.wake:
            host = self.get_host(h)
            self.wake_host(host)

    def sleep_host(self, host):
        result = self.cmd(host['ip'], 'sleep')

        if result == "OK":
            self.logger.info(f"{host['hostname']} ackowledged sleep request.")
            for i in range(5):
                self.logger.info(f"Waiting for ping to stop.. {i+1}/5")
                sleep((i+1) * 10)
                if self.ping_host(host) is None:
                    return True
            
            self.logger.info("Host is still responding.  Giving up.")
        
        return False

    def sleep_hosts(self):
        for h in self.config.args.sleep:
            host = self.get_host(h)
            self.sleep_host(host)
        
    def shutdown_host(self, host):
        result = self.cmd(host['ip'], 'shutdown')

        if result == "OK":
            self.logger.info(f"{host['hostname']} ackowledged shutdown request.")
            for i in range(5):
                self.logger.info(f"Waiting for ping to stop.. {i+1}/5")
                sleep((i+1) * 30)
                if self.ping_host(host) is None:
                    return True
            
            self.logger.info("Host is still responding.  Giving up.")
        
        return False

    def shutdown_hosts(self):
        for h in self.config.args.shutdown:
            host = self.get_host(h)
            self.shutdown_host(host)

    def reboot_host(self, host):
        self.cmd(host['ip'], 'reboot')

    def reboot_hosts(self):
        for h in self.config.args.reboot:
            host = self.get_host(h)
            self.reboot_host(host)
    
if __name__ == "__main__":
    config = Config()
    logger = Logger(config)
    
    if config.args.daemon:
        ws = WolwolfServer(config, logger)
        ws.run()
    else:
        wc = WolwolfClient(config, logger)
        wc.run()
