# -*- coding: utf-8 -*-

#################################################################################################

import hashlib
import json
import requests
import socket

import credentials as cred
import connectservice

#################################################################################################

ConnectionMode = {
    'Local': 0,
    'Remote': 1,
    'Manual': 2
}

class ConnectionManager(object):

    defaultTimeout = 20000


    def __init__(self, appName, appVersion, deviceName, deviceId,
            capabilities=None, devicePixelRatio=None):
        
        self.credentialProvider = cred.Credentials()
        self.appName = appName
        self.appVersion = appVersion
        self.deviceName = deviceName
        self.deviceId = deviceId
        self.capabilities = capabilities
        self.devicePixelRatio = devicePixelRatio


    def mergeServers(self, list1, list2):

        for i in range(0, len(list2), 1):
            self.credentialProvider.addOrUpdateServer(list1, list2[i])

        return list1

    def getHeaders(self, request):
        
        headers = request.setdefault('headers',{})

        if request['dataType'] == "json":
            headers['Accept'] = "application/json"

        headers['X-Application'] = self.addAppInfoToConnectRequest()
        headers['Content-type'] = request.get('contentType',
            'application/x-www-form-urlencoded; charset=UTF-8')

        return headers

    def requestUrl(self, request):

        if not request:
            print "Request cannot be null"
            return False

        headers = self.getHeaders(request)
        url = request['url']
        timeout = request.get('timeout', self.defaultTimeout)
        verify = False
        print "ConnectionManager requesting url: %s" % url

        if request['type'] == "GET":
            response = requests.get(url, json=request.get('data'), params=request.get('params'),
                headers=headers, timeout=timeout, verify=verify)
        elif request['type'] == "POST":
            response = requests.post(url, data=request.get('data'),
                headers=headers, timeout=timeout, verify=verify)
            
        print "ConnectionManager response status: %s" % response.status_code

        try:
            if response.status_code == requests.codes.ok:
                try:
                    return response.json()
                except requests.exceptions.ValueError:
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
            if server is None:
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
        sock.settimeout(1.0) # This controls the socket.timeout exception

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
        address = address.lower()

        if 'http' not in address:
            address = "http://%s" % address

        return address

    def tryConnect(self, url, timeout=None):

        url = self.getEmbyServerUrl(url, "system/info/public")
        print "tryConnect url: %s" % url

        if timeout is None:
            timeout = defaultTimeout

        return self.requestUrl({
            'type': "GET",
            'url': url,
            'dataType': "json",
            'timeout': timeout
        })

    def addAppInfoToConnectRequest(self):
        return "%s/%s" % (self.appName, self.appVersion)

    def getConnectServers(self, credentials):

        print "Begin getConnectServers"
        servers = []

        if not credentials.get('ConnectAccessToken') or not credentials.get('ConnectUserId'):
            return servers

        # Dummy up - don't involve connect
        '''url = self.getConnectUrl("servers?userId=%s" % credentials['ConnectUserId'])
        request = {
            'type': "GET",
            'url': url,
            'dataType': "json",
            'headers': {
                'X-Connect-UserToken': credentials['ConnectAccessToken']
            }
        }
        response = requestUrl(request)
        if response:
            for server in response:

                if server['UserType'].lower() == "guest":
                    userType = "Guest"
                else:
                    userType = "LinkedUser"

                servers.append({
                    'ExchangeToken': server['AccessKey'],
                    'ConnectServerId': server['Id'],
                    'Id': server['SystemId'],
                    'Name': server['Name'],
                    'RemoteAddress': server['Url'],
                    'LocalAddress': server['LocalAddress'],
                    'UserLinkType': userType
                })'''

        return servers

    def getAvailableServers(self):
        
        print "Begin getAvailableServers"

        # Clone the array
        credentials = self.credentialProvider.credentials()

        connectServers = self.getConnectServers(credentials)
        foundServers = self.findServers()

        servers = list(credentials['Servers'])
        self.mergeServers(servers, foundServers)
        self.mergeServers(servers, connectServers)

        servers = self.filterServers(servers, connectServers)

        credentials['Servers'] = servers
        self.credentialProvider.credentials(credentials)

        return servers

    def filterServers(self, servers, connectServers):
        
        filtered = []

        for server in servers:

            # It's not a connect server, so assume it's still valid
            if not server.get('ExchangeToken'):
                filtered.append(server)
                continue

            for connectServer in connectServers:
                if server['Id'] == connectServer['Id']:
                    filtered.append(server)
                    break
        else:
            return filtered

    def getConnectPasswordHash(self, password):

        password = connectservice.cleanPassword(password)
        
        return hashlib.md5(password).hexdigest()

    def saveUserInfoIntoCredentials(self, server, user):

        info = {
            'Id': user['Id'],
            'IsSignedInOffline': True
        }

        self.credentialProvider.addOrUpdateUser(server, info)

    def loginToConnect(self, username, password):

        if not username:
            return False

        if not password:
            return False

        md5 = self.getConnectPasswordHash(password)
        request = {
            'type': "POST",
            'url': self.getConnectUrl("user/authenticate"),
            'data': {
                'nameOrEmail': username,
                'password': md5
            },
            'dataType': "json"
        }
        result = self.requestUrl(request)
        print result
        if result:
            credentials = {}#self.credentialProvider.credentials()
            credentials['ConnectAccessToken'] = result['AccessToken']
            credentials['ConnectUserId'] = result['User']['Id']
            self.credentialProvider.credentials(credentials)
            return result
            #self.onConnectUserSignIn(result['User'])
        else:
            return False