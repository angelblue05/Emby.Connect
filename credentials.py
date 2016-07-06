# -*- coding: utf-8 -*-

#################################################################################################

from datetime import datetime
import json
import os

#################################################################################################


class Credentials(object):

    credentials = None
    path = "" # can be adjusted
    

    def __init__(self):
        pass


    def ensure(self):
        
        if self.credentials is None:
            try:
                with open(os.path.join(self.path, 'data.txt')) as infile:
                    jsonData = json.load(infile)
            except: # File is either empty or missing
                self.credentials = {}
                return

            print "credentials initialized with: %s" % jsonData
            self.credentials = jsonData
            self.credentials['Servers'] = self.credentials.setdefault('Servers', [])

    def get(self):

        self.ensure()
        return self.credentials

    def set(self, data):

        if data:
            self.credentials = data
            # Set credentials to file
            with open(os.path.join(self.path, 'data.txt'), 'w') as outfile:
                json.dump(data, outfile, indent=4, ensure_ascii=False)
        else:
            self.clear()

        print "credentialsupdated"

    def clear(self):

        self.credentials = None
        # Remove credentials from file
        with open(os.path.join(self.path, 'data.txt'), 'w'): pass

    def getCredentials(self, data=None):

        if data is not None:
            self.set(data)

        return self.get()

    def addOrUpdateServer(self, array, server):

        if not server.get('Id'):
            print "Server Id cannot be null or empty"
            return False

        for existing in array['Server']:
            if existing['Id'] == server['Id']:
                
                # Merge the data
                if server.get('DateLastAccessed'): # To review if item needs to be converted or not
                    existingDate = self.convertDate(
                        existing.get('DateLastAccessed', "2001-01-01T00:00:00Z"))
                    if serverDate > existingDate:
                        existing['DateLastAccessed'] = server['DateLastAccessed']

                existing['UserLinkType'] = server['UserLinkType']

                if server.get('AccessToken'):
                    existing['AccessToken'] = server['AccessToken']
                    existing['UserId'] = server['UserId']

                if server.get('ExchangeToken'):
                    existing['ExchangeToken'] = server['ExchangeToken']

                if server.get('RemoteAddress'):
                    existing['RemoteAddress'] = server['RemoteAddress']

                if server.get('ManualAddress'):
                    existing['ManualAddress'] = server['ManualAddress']

                if server.get('LocalAddress'):
                    existing['LocalAddress'] = server['LocalAddress']

                if server.get('Name'):
                    existing['Name'] = server['Name']

                if server.get('WakeOnLanInfos'):
                    existing['WakeOnLanInfos'] = server['WakeOnLanInfos']

                if server.get('LastConnectionMode') is not None:
                    existing['LastConnectionMode'] = server['LastConnectionMode']

                if server.get('ConnectServerId'):
                    existing['ConnectServerId'] = server['ConnectServerId']

                return existing
        else:
            array.append(server)
            return server

    def addOrUpdateUser(self, server, user):

        server['Users'] = server.setdefault('Users', [])

        for existing in server['Users']:
            if existing['Id'] == user['Id']:
                # Merge the data
                existing['IsSignedInOffline'] = True
                break
        else:
            server['Users'].append(user)

    def convertDate(self, date):

        try:
            date = datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")
        except TypeError:
            # TypeError: attribute of type 'NoneType' is not callable
            # Known Kodi/python error
            date = datetime(*(time.strptime(date, "%Y-%m-%dT%H:%M:%SZ")[0:6]))

        return date