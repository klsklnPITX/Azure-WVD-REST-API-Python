import msal
import requests
import json
from typing import Tuple
import sys


class Authenticator_MSAL_API_Requests:
    """ Authenticate to call REST API """

    def __init__(self, client_id, client_secret, tenant_id, scope_list=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self._authority = "https://login.microsoftonline.com/" + tenant_id
        if scope_list == None:
            scope_list = ['https://management.azure.com/.default']
        self.scope_list = scope_list
        self.access_token = None
        self.headers = None
        result = None

        msal_app = msal.ConfidentialClientApplication(
            self.client_id, client_credential=self.client_secret, authority=self._authority)

        result = msal_app.acquire_token_silent(
            scopes=self.scope_list, account=None)

        if not result:
            print("No suitable token exists in cache. Getting a new one from AAD.")
            result = msal_app.acquire_token_for_client(scopes=self.scope_list)

        if "access_token" in result:
            self.access_token = result["access_token"]
            self.headers = {'Authorization': 'Bearer ' + self.access_token,
                            'Content-Type': 'application/json'}
        else:
            print(result.get("error"))
            print(result.get("error_description"))
            print(result.get("correlation_id"))


class Azure_WVD_Requests(Authenticator_MSAL_API_Requests):
    """ Call REST API - WVD """

    def __init__(self, client_id, client_secret, tenant_id, subscription_id, scope_list=None):
        super().__init__(client_id, client_secret, tenant_id, scope_list)
        self.subscription_id = subscription_id

    def get_hostpool_vms_rgs(self, hostpool_type="All") -> Tuple[dict, list]:
        """ Get all/pooled/personal hostpools with sessionhost VM and according resource group. Default parameter = "All".
            Returns a dictionary with hostpool as key and its sessionhost VM as value in list. List has the according resource group. """

        sessionHosts_List = []
        sessionHosts_Dict = {}
        rg_list = []

        params = {'api-version': '2020-06-01'}
        url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/"
        r = requests.get(url, headers=self.headers, params=params)
        data = json.loads(json.dumps(r.json()))

        for rg in data["value"]:
            resource_group = rg["id"].split("/")[-1]
            params = {'api-version': '2019-01-23-preview'}
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.DesktopVirtualization/hostpools"
            r = requests.get(url, headers=self.headers, params=params)
            data = json.loads(json.dumps(r.json()))

            try:
                for hp in data['value']:
                    if hostpool_type == "All":
                        rg_list.append(resource_group)
                        url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.DesktopVirtualization/hostpools/{hp['name']}/sessionhosts"
                        r = requests.get(
                            url, headers=self.headers, params=params)
                        data = json.loads(json.dumps(r.json()))
                        for sh in data['value']:
                            try:
                                sessionHosts_List.append(
                                    sh['name'].split("/")[1].split("."[0])[0])
                            except:
                                continue
                        sessionHosts_Dict[hp['name']] = sessionHosts_List

                    elif hostpool_type == hp['properties']['hostPoolType']:
                        rg_list.append(resource_group)
                        url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.DesktopVirtualization/hostpools/{hp['name']}/sessionhosts"
                        r = requests.get(
                            url, headers=self.headers, params=params)
                        data = json.loads(json.dumps(r.json()))
                        for sh in data['value']:
                            try:
                                sessionHosts_List.append(
                                    sh['name'].split("/")[1].split("."[0])[0])
                            except:
                                continue
                        sessionHosts_Dict[hp['name']] = sessionHosts_List

                    sessionHosts_List = []
            except:
                e = sys.exc_info()
                print(e)
                continue

        return sessionHosts_Dict, rg_list

    def get_active_sessions(self, hostpool, sessionhost, resource_group) -> int:
        """ Get active user sessions on sessionhost. Disconnected sessions will still be visible, only signed out sessions will be seen as inactive. """
        current_activeSessions = None
        try:
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.DesktopVirtualization/hostpools/{hostpool}/sessionhosts"
            params = {'api-version': '2019-01-23-preview'}
            r = requests.get(url, headers=self.headers, params=params)
            dataSH = json.loads(json.dumps(r.json()))

            for vm in dataSH['value']:
                if vm['name'].split("/")[1].split("."[0])[0] == sessionhost:
                    current_activeSessions = vm['properties']['sessions']
                    return current_activeSessions
        except:
            e = sys.exc_info()
            print(
                f"Error getting active Sessions on machine {sessionhost}. {str(e)}")

    def check_allow_new_sessionstatus(self, hostpool, sessionhost, resource_group) -> bool:
        """ Checks wether a sessionhost is configured to allow new sessions or not. Returns bool true/false. """
        try:
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.DesktopVirtualization/hostpools/{hostpool}/sessionhosts"
            params = {'api-version': '2019-01-23-preview'}
            r = requests.get(url, headers=self.headers, params=params)
            data = json.loads(json.dumps(r.json()))
            for sh in data["value"]:
                if sessionhost == (sh["name"].split("/")[1].split(".")[0]):
                    sessionhost = sh["name"].split("/")[1]
                    url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.DesktopVirtualization/hostpools/{hostpool}/sessionhosts/{sessionhost}"
                    params = {'api-version': '2019-01-23-preview'}
                    r = requests.get(url, headers=self.headers, params=params)
                    data_sh = json.loads(json.dumps(r.json()))
                    state = data_sh["properties"]["allowNewSession"]
                    return True if state else False

        except:
            e = sys.exc_info()
            print(str(e))

    def get_wvd_usersessions(self, hostpoolDict, rg_list) -> Tuple[list, list, list]:
        """ Use return values of get_hostpool_vms_rgs as parameters. Returns sessionhost, session ID and user in sequence in lists.  """
        server_List = []
        sessionID_List = []
        user_List = []

        try:
            params = {'api-version': '2019-01-23-preview'}

            for rg_index, hostpool in enumerate(hostpoolDict):
                resource_group = rg_list[rg_index]
                url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.DesktopVirtualization/hostpools/{hostpool}/sessionhosts"
                r = requests.get(url, headers=self.headers, params=params)
                data = json.loads(json.dumps(r.json()))

                try:
                    for sessionhost in data["value"]:
                        sessionhostName = sessionhost["name"].split("/")[1]
                        url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.DesktopVirtualization/hostpools/{hostpool}/sessionhosts/{sessionhostName}/usersessions"
                        r = requests.get(
                            url, headers=self.headers, params=params)
                        data2 = json.loads(json.dumps(r.json()))

                        for activeUserSession in data2["value"]:
                            if activeUserSession["properties"]["applicationType"] == "Desktop":
                                server = activeUserSession["name"].split(
                                    "/")[1]
                                sessionID = activeUserSession["name"].split(
                                    "/")[2]
                                user = activeUserSession["properties"]["activeDirectoryUserName"].split("\\")[
                                    1]
                                server_List.append(server)
                                sessionID_List.append(sessionID)
                                user_List.append(user)
                except:
                    continue

            return server_List, sessionID_List, user_List

        except:
            e = sys.exc_info()
            print(f"Error getting user sessions for WVD: {str(e)}")
            return server_List, sessionID_List, user_List
