# -*- coding: utf-8 -*-

#################################################################################################

import hashlib
import json
import logging
import requests
import socket
from datetime import datetime

import credentials as cred
import connectservice

#################################################################################################

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
log = logging.getLogger(__name__)

#################################################################################################

ConnectionMode = {
    'Local': 0,
    'Remote': 1,
    'Manual': 2
}

def getServerAddress(server, mode):

    modes = {
        ConnectionMode['Local']: server.get('LocalAddress'),
        ConnectionMode['Remote']: server.get('RemoteAddress'),
        ConnectionMode['Manual']: server.get('ManualAddress')
    }
    return (modes.get(mode) or 
            server.get('ManualAddress',server.get('LocalAddress',server.get('RemoteAddress'))))   


class ConnectionManager(object):

    default_timeout = 20000
    apiClients = []


    def __init__(self, appName, appVersion, deviceName, deviceId, capabilities=None, devicePixelRatio=None):
        
        log.info("Begin ConnectionManager constructor")

        self.credentialProvider = cred.Credentials()
        self.appName = appName
        self.appVersion = appVersion
        self.deviceName = deviceName
        self.deviceId = deviceId
        self.capabilities = capabilities
        self.devicePixelRatio = devicePixelRatio

    def setFilePath(self, path):
        # Set where to save persistant data
        self.credentialProvider.setPath(path)

    def mergeServers(self, list1, list2):

        for i in range(0, len(list2), 1):
            try:
                self.credentialProvider.addOrUpdateServer(list1, list2[i])
            except KeyError:
                continue

        return list1

    def _updateServerInfo(self, server, systemInfo):

        server['Name'] = systemInfo['ServerName']
        server['Id'] = systemInfo['Id']

        if systemInfo.get('LocalAddress'):
            server['LocalAddress'] = systemInfo['LocalAddress']
        if systemInfo.get('WanAddress'):
            server['RemoteAddress'] = systemInfo['WanAddress']
        if systemInfo.get('MacAddress'):
            server['WakeOnLanInfos'] = [{'MacAddress': systemInfo['MacAddress']}]

    def _getHeaders(self, request):
        
        headers = request.setdefault('headers', {})

        if request['dataType'] == "json":
            headers['Accept'] = "application/json"

        request.pop('dataType')

        headers['X-Application'] = self._addAppInfoToConnectRequest()
        headers['Content-type'] = request.get('contentType',
            'application/x-www-form-urlencoded; charset=UTF-8')

    def requestUrl(self, request):

        if not request:
            raise AttributeError("Request cannot be null")

        self._getHeaders(request)
        request['timeout'] = request.get('timeout') or self.default_timeout
        request['verify'] = False

        log.info("ConnectionManager requesting %s" % request)
        action = request['type']
        request.pop('type')

        try:
            r = self._requests(action, **request)
            log.info("ConnectionManager response status: %s" % r.status_code)
            r.raise_for_status()
        
        except Exception as e: # Elaborate on exceptions?
            log.exception(e)
            raise

        else:
            try:
                return r.json()
            except requests.exceptions.ValueError:
                r.content # Read response to release connection
                return

    def _requests(self, action, **kwargs):

        if action == "GET":
            r = requests.get(**kwargs)
        elif action == "POST":
            r = requests.post(**kwargs)

        return r

    def getEmbyServerUrl(self, baseUrl, handler):
        return "%s/emby/%s" % (baseUrl, handler)

    def getConnectUrl(self, handler):
        return "https://connect.emby.media/service/%s" % handler

    def _findServers(self, foundServers):

        servers = []

        for foundServer in foundServers:

            server = self._convertEndpointAddressToManualAddress(foundServer)

            info = {
                'Id': foundServer['Id'],
                'LocalAddress': server or foundServer['Address'],
                'Name': foundServer['Name']
            }
            info['LastConnectionMode'] = ConnectionMode['Manual'] if info.get('ManualAddress') else ConnectionMode['Local']
            
            servers.append(info)
        else:
            return servers

    def _convertEndpointAddressToManualAddress(self, info):
        
        if info.get('Address') and info.get('EndpointAddress'):
            address = info['EndpointAddress'].split(':')[0]

            # Determine the port, if any
            parts = info['Address'].split(':')
            if len(parts) > 1:
                portString = parts[len(parts)-1]

                try:
                    address += ":%s" % int(portString)
                    return self._normalizeAddress(address)
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
        
        log.info("MultiGroup      : %s" % str(MULTI_GROUP))
        log.info("Sending UDP Data: %s" % MESSAGE)
        sock.sendto(MESSAGE, MULTI_GROUP)
        
        servers = []
        while True:
            try:
                data, addr = sock.recvfrom(1024) # buffer size
                servers.append(json.loads(data))
            
            except socket.timeout:
                log.info("Found Servers: %s" % servers)
                return servers
            
            except Exception as e:
                log.error("Error trying to find servers: %s" % e)
                return servers

    def _normalizeAddress(self, address):
        # Attempt to correct bad input
        address = address.strip()
        address = address.lower()

        if 'http' not in address:
            address = "http://%s" % address

        return address

    def _tryConnect(self, url, timeout=None):

        url = self.getEmbyServerUrl(url, "system/info/public")
        log.info("tryConnect url: %s" % url)

        return self.requestUrl({
            
            'type': "GET",
            'url': url,
            'dataType': "json",
            'timeout': timeout
        })

    def _addAppInfoToConnectRequest(self):
        return "%s/%s" % (self.appName, self.appVersion)

    def _getConnectServers(self, credentials):

        log.info("Begin getConnectServers")
        
        servers = []

        if not credentials.get('ConnectAccessToken') or not credentials.get('ConnectUserId'):
            return servers

        # TODO: Comment out once testing is over.
        url = self.getConnectUrl("servers?userId=%s" % credentials['ConnectUserId'])
        request = {

            'type': "GET",
            'url': url,
            'dataType': "json",
            'headers': {
                'X-Connect-UserToken': credentials['ConnectAccessToken']
            }
        }
        for server in self.requestUrl(request):

            servers.append({

                'ExchangeToken': server['AccessKey'],
                'ConnectServerId': server['Id'],
                'Id': server['SystemId'],
                'Name': server['Name'],
                'RemoteAddress': server['Url'],
                'LocalAddress': server['LocalAddress'],
                'UserLinkType': "Guest" if server['UserType'].lower() == "guest" else "LinkedUser"
            })

        return servers

    def getAvailableServers(self):
        
        log.info("Begin getAvailableServers")

        # Clone the array
        credentials = self.credentialProvider.getCredentials()

        connectServers = self._getConnectServers(credentials)
        foundServers = self._findServers(self.serverDiscovery())

        servers = list(credentials['Servers'])
        self.mergeServers(servers, foundServers)
        self.mergeServers(servers, connectServers)

        servers = self._filterServers(servers, connectServers)

        # TODO: Server sort by DateLastAccessed

        credentials['Servers'] = servers
        self.credentialProvider.getCredentials(credentials)

        return servers

    def _filterServers(self, servers, connectServers):
        
        filtered = []

        for server in servers:

            # It's not a connect server, so assume it's still valid
            if server.get('ExchangeToken') is None:
                filtered.append(server)
                continue

            for connectServer in connectServers:
                if server['Id'] == connectServer['Id']:
                    filtered.append(server)
                    break
        else:
            return filtered

    def _getConnectPasswordHash(self, password):

        password = connectservice.cleanPassword(password)
        
        return hashlib.md5(password).hexdigest()

    def _saveUserInfoIntoCredentials(self, server, user):

        info = {
            'Id': user['Id'],
            'IsSignedInOffline': True
        }

        self.credentialProvider.addOrUpdateUser(server, info)

    def _onLocalUserSignIn(self, server, connectionMode, user):

        # Ensure this is created so that listeners of the event can get the apiClient instance
        pass

    def connectToServer(self, server, options):

        log.info("being connectToServer")

        tests = []

        if server.get('LastConnectionMode') is not None:
            #tests.append(server['LastConnectionMode'])
            pass
        if ConnectionMode['Manual'] not in tests:
            tests.append(ConnectionMode['Manual'])
        if ConnectionMode['Local'] not in tests:
            tests.append(ConnectionMode['Local'])
        if ConnectionMode['Remote'] not in tests:
            tests.append(ConnectionMode['Remote'])

        # TODO: begin to wake server

        options = options or {}

        log.info("beginning connection tests")
        self._testNextConnectionMode(tests, 0, server, options)

    def _stringEqualsIgnoreCase(self, str1, str2):

        return (str1 or "").lower() == (str2 or "").lower()

    def _testNextConnectionMode(self, tests, index, server, options):

        if index >= len(tests):
            log.info("Tested all connection modes. Failing server connection.")
            return False

        mode = tests[index]
        address = getServerAddress(server, mode)
        enableRetry = False
        skipTest = False
        timeout = self.default_timeout

        if mode == ConnectionMode['Local']:
            enableRetry = True
            timeout = 8000

            if self._stringEqualsIgnoreCase(address, server['ManualAddress']):
                log.info("skipping LocalAddress test because it is the same as ManualAddress")
                skipTest = True

        elif mode == ConnectionMode['Manual']:

            if self._stringEqualsIgnoreCase(address, server['LocalAddress']):
                enableRetry = True
                timeout = 8000

        if skipTest or not address:
            log.info("skipping test at index: %s" % index)
            self._testNextConnectionMode(tests, index+1, server, options)
            return

        log.info("testing connection mode %s with server %s" % (mode, server['Name']))
        try:
            result = self._tryConnect(address, timeout)
            # TODO: compare server versions
            log.info("calling onSuccessfulConnection with connection mode %s with server %s"
                    % (mode, server['Name']))
            self._onSuccessfulConnection(server, result, mode, options)
        except Exception:
            log.error("test failed for connection mode %s with server %s" % (mode, server['Name']))

            if enableRetry:
                # TODO: wake on lan and retry
                self._testNextConnectionMode(tests, index+1, server, options)
            else:
                self._testNextConnectionMode(tests, index+1, server, options)

    def _onSuccessfulConnection(self, server, systemInfo, connectionMode, options):
        # TODO: Review to maybe simplify the duplicated lines
        credentials = self.credentialProvider.getCredentials()
        options = options or {}

        if credentials.get('ConnectAccessToken') and options.get('enableAutoLogin') is not False:
            
            if self._ensureConnectUser(credentials) is not False:

                if server.get('ExchangeToken'):
                    
                    if self._addAuthenticationInfoFromConnect(server, connectionMode, credentials) is not False:
                        
                        self._afterConnectValidated(server, credentials, systemInfo, connectionMode, True, options)
                    else:
                        self._afterConnectValidated(server, credentials, systemInfo, connectionMode, True, options)
                else:
                    self._afterConnectValidated(server, credentials, systemInfo, connectionMode, True, options)
        else:
            self._afterConnectValidated(server, credentials, systemInfo, connectionMode, True, options)

    def _afterConnectValidated(self, server, credentials, systemInfo, connectionMode, verifyLocalAuthentication, options):

        options = options or {}

        if not options.get('enableAutoLogin'):
            server['UserId'] = None
            server['AccessToken'] = None
        
        elif (verifyLocalAuthentication and server.get('AccessToken') and 
            options.get('enableAutoLogin') is not False):

            if self._validateAuthentication(server, connectionMode) is not False:
                self._afterConnectValidated(server, credentials, systemInfo, connectionMode, False, options)

            return

        self.updateServerInfo(server, systemInfo)
        server['LastConnectionMode'] = connectionMode

        if options.get('updateDateLastAccessed') is not False:
            server['DateLastAccessed'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')

        self.credentialProvider.addOrUpdateServer(credentials['Servers'], server)
        self.credentialProvider.getCredentials(credentials)

        # TODO: apiClient

    def _validateAuthentication(self, server, connectionMode):

        url = getServerAddress(server, connectionMode)
        request = {

            'type': "GET",
            'url': url,
            'dataType': "json",
            'headers': {
                'X-MediaBrowser-Token': server['AccessToken']
            }
        }
        try:
            systemInfo = self.requestUrl(request)
            self._updateServerInfo(server, systemInfo)

            if server.get('UserId'):
                user = self.requestUrl({

                    'type': "GET",
                    'url': self.getEmbyServerUrl(url, "users/%s" % server['UserId']),
                    'dataType': "json",
                    'headers': {
                        'X-MediaBrowser-Token': server['AccessToken']
                    }
                })
                # TODO: _onLocalUserSignIn
        except Exception:
            server['UserId'] = None
            server['AccessToken'] = None
            return False

    def getImageUrl(self, localUser):

        if self.connectUser.get('ImageUrl'):
            return {
                'url': self.connectUser['ImageUrl']
            }
        if localUser.get('PrimaryImageTag'):
            # TODO: apiClient
            return {
                'url': url,
                'supportsParams': True
            }

        return {
            'url': None,
            'supportsParams': False
        }

    def loginToConnect(self, username, password):

        if not username:
            raise AttributeError("username cannot be empty")

        if not password:
            raise AttributeError("password cannot be empty")

        md5 = self._getConnectPasswordHash(password)
        request = {
            'type': "POST",
            'url': self.getConnectUrl("user/authenticate"),
            'data': {
                'nameOrEmail': username,
                'password': md5
            },
            'dataType': "json"
        }
        try:
            result = self.requestUrl(request)
        except Exception: # Failed to login
            return False
        else:
            credentials = self.credentialProvider.getCredentials()
            credentials['ConnectAccessToken'] = result['AccessToken']
            credentials['ConnectUserId'] = result['User']['Id']
            self.credentialProvider.getCredentials(credentials)
            # Signed in
            self._onConnectUserSignIn(result['User'])
        
        return result

    def _onConnectUserSignIn(self, user):

        self.connectUser = user
        log.info("connectusersignedin %s" % user)

    def _getConnectUser(self, userId, accessToken):

        if not userId:
            raise AttributeError("null userId")

        if not accessToken:
            raise AttributeError("null accessToken")

        url = self.getConnectUrl('user?id=%s' % userId)

        return self.requestUrl({
            
            'type': "GET",
            'url': url,
            'dateType': "json",
            'headers': {
                'X-Connect-UserToken': accessToken
            }
        })

    def _addAuthenticationInfoFromConnect(self, server, connectionMode, credentials):

        if not server.get('ExchangeToken'):
            raise KeyError("server['ExchangeToken'] cannot be null")

        if not credentials.get('ConnectUserId'):
            raise KeyError("credentials['ConnectUserId'] cannot be null")

        url = getServerAddress(server, connectionMode)
        url = self.getEmbyServerUrl(url, "Connect/Exchange?format=json")
        try:
            auth = self.requestUrl({

                'url': url,
                'type': "GET",
                'dataType': "json",
                'headers': {
                    'X-MediaBrowser-Token': server['ExchangeToken']
                }
            })
        except Exception:
            server['UserId'] = None
            server['AccessToken'] = None
            return False
        else:
            server['UserId'] = auth['LocalUserId']
            server['AccessToken'] = auth['AccessToken']
            return auth

    def _ensureConnectUser(self, credentials):

        if self.connectUser and self.connectUser['Id'] == credentials['ConnectUserId']:
            return

        elif credentials.get('ConnectUserId') and credentials.get('ConnectAccessToken'):

            self.connectUser = None

            try:
                result = self._getConnectUser(credentials['ConnectUserId'], credentials['ConnectAccessToken'])
                self._onConnectUserSignIn(result)
            except Exception:
                return False