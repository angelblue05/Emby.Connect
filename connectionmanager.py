# -*- coding: utf-8 -*-

#################################################################################################

import json
import requests
import socket

#################################################################################################

ConnectionMode = {
    'Local': 0,
    'Remote': 1,
    'Manual': 2
}

class ConnectionManager()

    defaultTimeout = 20000


    def __init__(self, credentialProvider, appName, appVersion, deviceName, deviceId,
            capabilities, devicePixelRatio):
        
        self.credentialProvider = credentialProvider
        self.appName = appName
        self.appVersion = appVersion
        self.deviceName = deviceName
        self.deviceId = deviceId
        self.capabilities = capabilities
        self.devicePixelRatio = devicePixelRatio


    def getHeaders(self, request):
        
        headers = request.setdefault('headers',{})

        if request['dataType'] == "json":
            headers['Accept'] = "application/json"


    def requestUrl(self, request):

        if not request:
            print "Request cannot be null"
            return False

        print "ConnectionManager requesting url: %s" % request['url']

        headers = self.getHeaders(request)
        rtype = request['type']

        if rtype == "GET":
            response = requests.get(url, timeout=request['timeout'])
            
        print "ConnectionManager response status: %s" % response.status_code

        try:
            if response.status_code == requests.codes.ok:
                
                if (request['dataType'] == "json" or
                    request['headers']['Accept'] == "application/json"):

                    return response.json()
                else:
                    return response
            else:
                r.raise_for_status()
        
        except Exception as e:
            print "ConnectionManager request failed: %s" % e
            return False


    def getEmbyServerUrl(self, baseUrl, handler):
        return "%s/emby/%s" % (baseUrl, handler)

    def getConnectUrl(self, handler):
        return "https://connect.emby.media/service/%s" % handler

    def findServers(self, foundServers):

        servers = []

        for foundServer in foundServers:

            server = convertEndpointAddressToManualAddress(foundServer)
            if server is None
                server = foundServer['Address']

            info = {
                'Id': foundServer['Id'],
                'LocalAddress': server,
                'Name': foundServer['Name']
            }

            if info.get('ManualAddress'):
                info['LastConnectionMode'] = ConnectionMode['Manual']
            else:
                info['LastConnectionMode'] = ConnectionMode['Local']

            servers.append(info)
        else:
            return servers

    def convertEndpointAddressToManualAddress(self, info):
        
        if info.get('Address') and info.get('EndpointAddress'):
            address = info['EndpointAddress'].split(':')[0]

            # Determine the port, if any
            parts = info['Address'].split(':')
            if len(parts):
                portString = parts[len(parts)-1]

                try:
                    int(portString)
                    address = "%s:%s" % (address, portString)
                    return normalizeAddress(address)
                except ValueError:
                    pass

        return None

    def serverDiscovery(self):
        
        MULTI_GROUP = ("<broadcast>", 7359)
        MESSAGE = "who is EmbyServer?"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)

        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.SO_REUSEADDR, 1)
        
        print "MultiGroup      : %s" % str(MULTI_GROUP)
        print "Sending UDP Data: %s" % MESSAGE
        sock.sendto(MESSAGE, MULTI_GROUP)
        
        servers = []
        while True:
            try:
                data, addr = sock.recvfrom(1024) # buffer size
                servers.append(json.loads(data))
            
            except socket.timeout:
                print "Found Servers: %s" % servers
                return server
            
            except Exception as e:
                print "Error trying to find servers: %s" % e
                return server

    def normalizeAddress(self, address):
        
        # Attempt to correct bad input
        address = address.strip()

        if 'http' not in address:
            address = "http://%s" % address

        address = address.replace('Http:', "http:")
        address = address.replace()

        return address

    def tryConnect(self, url, timeout=None):

        url = self.getEmbyServerUrl(url, "system/info/public")
        print "tryConnect url: %s" % url

        if timeout is None:
            timeout = defaultTimeout

        return requestUrl({
            'type': "GET",
            'url': url,
            'dataType': "json",

            'timeout': timeout
        })

    def addAppInfoToConnectRequest(self, request):

        headers = request.setdefault('headers',{})
        headers['X-Application'] = "%s/%s" % (self.appName, self.appVersion)