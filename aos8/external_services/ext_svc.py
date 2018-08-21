#!/usr/bin/env python

def get_rfc3576_client_profiles(session, config_path):
    get_url = 'configuration/object/rfc3576_client_prof'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve RFC3576 client profile list')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: RFC3576 client profile list retrieved successfully')
        return response_json['_data']['rfc3576_client_prof']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve RFC3576 client profile list')
        return None

def post_rfc3576_client_profile(session, config_path, action, server_ip, **kwargs):

    if (action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

    if (action == 'add'):

        payload = {
            '_action': 'add',
            'server_ip': server_ip
        } 
    
        for key, value in kwargs.items():
            if(key == 'rfc3576_secret'):
                payload[key] = {'key': value}
            elif(key == 'rfc3576_radsec_enable'):
                if (value == True):
                    payload[key] = {}
                else:
                    payload[key] = {"_action": "delete"}
            elif(key == 'replay_protect'):
                if (value == True):
                    payload[key] = {}
                else:
                    payload[key] = {"_action": "delete"}
            elif(key == 'event_timestamp_check'):
                if (value == True):
                    payload[key] = {}
                else:
                    payload[key] = {"_action": "delete"}
            elif(key == 'window_duration'):
                payload[key] = {'WindowDuration': value}
            elif(key == 'rfc3576_client_prof_clone'):
                payload[key] = {'source': value}               
            else:
                result_str = f'\'{key}\' is not a configurable setting for the RFC3576 client profile'
                result = {'result_status': 1, 'result_str': result_str} 
                return result 

    elif (action == 'delete'):
        if (session.api_verbose == True):
            print(f'Verbose: Checking to see if RFC3576 client profile \'{server_ip}\' already exists')

        rfc3576_client_profile_list = get_rfc3576_client_profiles(session,config_path)

        if not rfc3576_client_profile_list:
            result_str = f'RFC3576 client profile \'{server_ip}\' does not exist'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

        else:
            for client in rfc3576_client_profile_list:
                if (client['server_ip'] == server_ip):
                    break        
            else:
                result_str = f'RFC3576 client profile \'{server_ip}\' does not exist'
                result = {'result_status': 1, 'result_str': result_str} 
                return result
    
        if (session.api_verbose == True):
            print(f'Verbose: RFC3576 client profile \'{server_ip}\' exists')
    

        payload = {
            '_action': 'delete',
            "server_ip": server_ip
        }
    
    post_url = 'configuration/object/rfc3576_client_prof'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} RFC3576 client profile \'{server_ip}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()

        status_str = response_json['_global_result']['status_str']
        result_str = f'{action.upper()} RFC3576 client profile \'{server_ip}\' - {status_str}'

        if (response_json['_global_result']['status'] == 0):
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result = {'result_status': 1, 'result_str': result_str} 
            return result

    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
