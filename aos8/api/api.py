#!/usr/bin/env python
import requests

'''
API session to perform login/logout and GET/POST operations
on Aruba Networks AOS 8.x devices
'''
class AOS8_API_Session_V1:
    def __init__(self, username, password, device_url, api_check_ssl, api_verbose):

        self.username = username
        self.password = password
        
        self.api_session = None
        self.api_token = None
    
        self.device_url = device_url
        self.api_url = 'https://' + device_url + ':4343/v1/'
        self.api_check_ssl = api_check_ssl
        self.api_verbose = api_verbose
    
    def login(self):
        self.api_session = requests.Session()

        # Set URL for login
        login_url = self.api_url + 'api/login?username=' + self.username + '&password=' + self.password

        # Attempt login to Aruba AOS 8.x device
        try:
            if(self.api_verbose == True):
                print(f'Verbose: Attempting to login to \'{self.device_url}\'')
            
            login_request_response = self.api_session.get(login_url, verify=self.api_check_ssl)
        except requests.exceptions.ConnectionError:
            print(f'Unable to connect to \'{self.api_url}\'\nExiting...')
            return False             
        else:
            # Parse JSON response to GET
            login_json_response = login_request_response.json()

            # Successful login
            if (login_json_response['_global_result']['status'] == '0'):
                # Save UID for session
                self.api_token = login_json_response['_global_result']['UIDARUBA']
                if (self.api_verbose == True):
                    print(f'Verbose: Successful login to \'{self.device_url}\'')
                return True
            
            # Unsuccessful login
            else:
                print(f'Unable to login to \'{self.api_url}\'\nCheck supplied credentials.')
                return False
    
    def logout(self):
        
        # Set URL for logout
        logout_url = self.api_url + 'api/logout'

        if (self.api_session != None):

            # Attempt logout
            try:
                logout_request_response = self.api_session.get(logout_url)
            except requests.exceptions.ConnectionError:
                print(f'Unable to connect to \'{self.api_url}\'\nExiting...')
                return False             
            else:
                # Parse JSON response
                logout_json_response = logout_request_response.json()

                # Successful logout
                if (logout_json_response['_global_result']['status'] == '0'):
                    self.api_token = None
                    if (self.api_verbose == True):
                        print(f'Verbose: Successfully logged out of {self.device_url!r}')
                    return True
                # Unsuccessful logout
                else:
                    print(f'Unable to logout of \'{self.api_url}\'')
                    return False
        
        else:
            print('Logout ignored - no active session')

    def get(self, api_path, config_path=None):
        
        # Login if not already
        if (self.api_token == None):
            self.login()
    
        # Set URL for GET
        if (config_path is not None):
            node_path = '?config_path=' + config_path
            get_url = self.api_url + api_path + node_path + '&UIDARUBA=' + self.api_token
        else:
            get_url = self.api_url + api_path + '?UIDARUBA=' + self.api_token
        
        # Send GET to API session
        get_request_response = self.api_session.get(get_url)

        return get_request_response

    def post(self,api_path, config_path, payload):
        
        # Login if not already       
        if (self.api_token == None):
            self.login()
        node_path = '?config_path=' + config_path

        # Set URL for POST
        post_url = self.api_url + api_path + node_path + '&UIDARUBA=' + self.api_token

        # Send POST to API session
        post_request_response = self.api_session.post(post_url,json=payload)

        return post_request_response

    def show_cli_command(self,command):
        modified_command = command.replace(" ", "+")

        # Set URL for show command GET
        show_command_url = self.api_url + 'configuration/showcommand?command=' + modified_command + "&UIDARUBA=" + self.api_token

        # Send show command GET to API session
        show_command_request_response = self.api_session.get(show_command_url)
        
        # Parse JSON response to GET
        show_command_json_response = show_command_request_response.json()
      
        return show_command_json_response

    def write_mem(self, config_path):
        
        # Set URL for write memory POST
        api_path = 'configuration/object/write_memory'

        # Send write memory POST to API session
        write_mem_request_response = self.post(api_path,config_path,{})

        # Parse JSON response to POST
        write_mem_json_response = write_mem_request_response.json()
      
        return write_mem_json_response