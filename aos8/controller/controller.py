#!/usr/bin/env python

def post_snmp_server_enable_trap(session, config_path):

    payload = {}

    post_url = 'configuration/object/snmp_ser_enable_trap'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to enable SNMP traps')

    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'Enable SNMP traps - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'Enable SNMP traps - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def post_copy_running_tftp(session, config_path, tftp_host, filename):

    payload = {
        'tftphost': tftp_host,
        'filename': filename
        }

    post_url = 'configuration/object/copy_running_tftp'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to copy running-config to TFTP server')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'Copy running-config to TFTP server - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'Copy running-config to TFTP server - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result




def get_syscontact(session, config_path):

    get_url = 'configuration/object/syscontact'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve syscontact')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: syscontact retrieved successfully')
        return response_json['_data']['syscontact']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrive syscontact')
        return None

def post_syscontact(session, config_path, action='add', syscontact=" "):
    
    if (action != 'add' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

    payload = {
        '_action': 'add',
        'syscontact': syscontact
        }
    post_url = 'configuration/object/syscontact'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} syscontact')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} syscontact - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} syscontact - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_ip_domain_name(session, config_path):

    get_url = 'configuration/object/ip_domain_name'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve IP domain name')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: IP domain name retrieved successfully')
        return response_json['_data']['ip_domain_name']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrive IP domain name')
        return None

def post_ip_domain_name(session, config_path, action, domain_name):

    if (action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

    if (action == 'add'):

        payload = {
            '_action': 'add',
            'name': domain_name
        } 
    
    elif (action == 'delete'):

        payload = {
            '_action': 'delete',
            'name': domain_name
        } 
    post_url = 'configuration/object/ip_domain_name'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} IP domain name \'{domain_name}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} IP domain name \'{domain_name}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} IP domain name \'{domain_name}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def post_snmp_server_source_controller_ip(session, config_path):

    payload = {}

    post_url = 'configuration/object/snmp_ser_source_controller_ip'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to set SNMP server source as controller IP')

    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'SNMP server source as controller IP - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'SNMP server source as controller IP - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result