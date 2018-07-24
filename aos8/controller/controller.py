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
                print('Verbose: Unable to retrieve syscontact')
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
                print('Verbose: Unable to retrieve IP domain name')
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

def post_copy_ftp_system(session, config_path, partition_num, ftp_host, ftp_user, ftp_password, filename):

    payload = {
        'partition_num': partition_num,
        'ftphost': ftp_host,
        'user': ftp_user,
        'filename': filename,
        'passwd': ftp_password
        }

    post_url = 'configuration/object/copy_ftp_system'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to FTP image to system partition {partition_num}')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'FTP image to system partition {partition_num} - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'FTP image to system partition {partition_num} - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_snmp_server_host_snmpv2c(session, config_path):

    get_url = 'configuration/object/snmp_ser_host_snmpv2c'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve SNMP v2c host list')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: SNMP v2c host list retrieved successfully')
        return response_json['_data']['snmp_ser_host_snmpv2c']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve SNMP v2c host list')
        return None

def post_snmp_server_host_snmpv2c(session, config_path, action, snmp_host_ip, snmp_host_name, **kwargs):
    
    if ( action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
    
    if (action == 'add'):
        
        payload = {
        '_action': 'add',
        'ipAddress': snmp_host_ip,
        'name': snmp_host_name
        }
    
        for key, value in kwargs.items():
            if(key == 'portnumber'):
                payload[key] = value
            elif(key == 'inform'):
                payload[key] = value
            elif(key == 'secs'):
                payload[key] = value
            elif(key == 'count'):
                payload[key] = value
            else:
                result_str = f'\'{key}\' is not a configurable setting for a SNMP v2c host'
                result = {'result_status': 1, 'result_str': result_str} 
                return result 

    elif (action == 'delete'):
        if (session.api_verbose == True):
            print(f'Verbose: Checking to see if SNMP v2c host \'{snmp_host_ip}\' already exists')

        snmp_server_v2c_host_list = get_snmp_server_host_snmpv2c(session,config_path)

        payload = {
        '_action': 'delete',
        'ipAddress': snmp_host_ip,
        'name': snmp_host_name
        }

        if not snmp_server_v2c_host_list:
            result_str = f'SNMP v2c host \'{snmp_host_ip}\' does not exist'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

        else:
            for host in snmp_server_v2c_host_list:
                if (host['ipAddress'] == snmp_host_ip):
                    if host.get('portnumber'):
                        payload['portnumber'] = host.get('portnumber')
                    break        
            else:
                result_str = f'SNMP v2c host \'{snmp_host_ip}\' does not exist'
                result = {'result_status': 1, 'result_str': result_str} 
                return result
    
        if (session.api_verbose == True):
            print(f'Verbose: SNMP v2c host \'{snmp_host_ip}\' exists')
    
    post_url = 'configuration/object/snmp_ser_host_snmpv2c'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} SNMP v2c host \'{snmp_host_ip}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} SNMP v2c host \'{snmp_host_ip}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} SNMP v2c host \'{snmp_host_ip}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def post_copy_flash_scp(session, config_path, scp_host, scp_username, scp_password, srcfilename, dstfilename):

    payload = {
        'scphost': scp_host,
        'username': scp_username,
        'passwd': scp_password,       
        'srcfilename': srcfilename,
        'destfilename': dstfilename,
        }

    post_url = 'configuration/object/copy_flash_scp'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to SCP copy flash:/{srcfilename} to {scp_host}:/{dstfilename}')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'SCP copy flash:/{srcfilename} to {scp_host}:/{dstfilename} - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'SCP copy flash:/{srcfilename} to {scp_host}:/{dstfilename} - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def post_copy_running_flash(session, config_path, filename):

    payload = {
        '_action': 'add',
        'filename': filename
        }

    post_url = 'configuration/object/copy_running_flash'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to copy running-config to flash:/{filename}')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'copy running-config to flash:/{filename} - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'copy running-config to flash:/{filename} - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_hostname(session, config_path):

    get_url = 'configuration/object/hostname'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve hostname')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: hostname retrieved successfully')
        return response_json['_data']['hostname']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve hostname')
        return None

def post_hostname(session, config_path, hostname):
    
    payload = {
        '_action': 'add',
        'hostname': hostname
    }
    
    post_url = 'configuration/object/hostname'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to add hostname \'{hostname}\' to \'{config_path}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'Add hostname \'{hostname}\' to \'{config_path}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'Add hostname \'{hostname}\' to \'{config_path}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_masterip(session, config_path):

    get_url = 'configuration/object/masterip'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve masterip configuration')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: masterip configuration retrieved successfully')
        return response_json['_data']['masterip']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve masterip configuration')
        return None

def post_masterip(session, config_path, masterip_val, **kwargs):
    
    payload = {
        '_action': 'add',
        'masterip_val': masterip_val
    }
    
    for key, value in kwargs.items():
        if(key == 'key'):
            payload[key] = value
        elif(key == 'id'):
            payload[key] = value
        elif(key == 'local-fqdn'):
            payload[key] = value
        elif(key == 'peer-mac-1' and value == True):
            payload[key] = value
        elif(key == 'peermac-1'):
            payload[key] = value
        elif(key == 'peermac-2'):
            payload[key] = value
        else:
            result_str = f'\'{key}\' is not a configurable setting for a SNMP v2c host'
            result = {'result_status': 1, 'result_str': result_str} 
            return result 

    post_url = 'configuration/object/masterip'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to add masterip \'{masterip_val}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'Add masterip \'{masterip_val}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'Add masterip \'{masterip_val}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_controller_ip(session, config_path):

    get_url = 'configuration/object/ctrl_ip'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve controller IP')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: controller IP retrieved successfully')
        return response_json['_data']['ctrl_ip']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve controller IP')
        return None

def post_controller_ip(session, config_path, **kwargs):
    
    payload = {
        '_action': 'add',
    }
    
    if not kwargs:
        result_str = 'Controller IP must be configured with either interface VLAN or loopback interface.'
        result = {'result_status': 1, 'result_str': result_str} 
        return result 

    for key, value in kwargs.items():
        if(key == 'id'):
            payload[key] = value
            break
        elif(key == 'loopback' and value == True):
            payload[key] = value
        else:
            result_str = 'Controller IP must be configured with either interface VLAN or loopback interface.'
            result = {'result_status': 1, 'result_str': result_str} 
            return result 

    post_url = 'configuration/object/ctrl_ip'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to add controller IP')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'Add controller IP - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'Add controller IP - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_snmp_server_community(session, config_path):

    get_url = 'configuration/object/snmp_ser_community'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve SNMP community string')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: SNMP community string retrieved successfully')
        return response_json['_data']['snmp_ser_community']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve SNMP community string')
        return None

def post_snmp_server_community(session, config_path, action, snmp_community_string):
    
    if ( action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
    
    if (action == 'add'):
        
        payload = {
        '_action': 'add',
        'name': snmp_community_string
        }
    
    elif (action == 'delete'):

        payload = {
        '_action': 'delete',
        'name': snmp_community_string
        }

    post_url = 'configuration/object/snmp_ser_community'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} SNMP community string \'{snmp_community_string}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} SNMP community string \'{snmp_community_string}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} SNMP community string \'{snmp_community_string}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_snmp_server_host_snmpv3(session, config_path):

    get_url = 'configuration/object/snmp_ser_host_snmpv3'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve SNMP v3 host list')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: SNMP v3 host list retrieved successfully')
        return response_json['_data']['snmp_ser_host_snmpv3']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve SNMP v3 host list')
        return None

def post_snmp_server_host_snmpv3(session, config_path, action, snmp_host_ip, snmp_host_name, **kwargs):
    
    if ( action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
    
    if (action == 'add'):
        
        payload = {
        '_action': 'add',
        'ipAddress': snmp_host_ip,
        'name': snmp_host_name
        }

        if (kwargs.get('inform') == False and not kwargs.get('engineid')):
            result_str = f'SNMP engine ID must be supplied when not using informs'
            result = {'result_status': 1, 'result_str': result_str} 
            return result 
    
        for key, value in kwargs.items():
            if(key == 'portnumber'):
                payload[key] = value
            elif(key == 'inform'):
                payload[key] = value
            elif(key == 'secs'):
                payload[key] = value
            elif(key == 'count'):
                payload[key] = value
            elif(key == 'engineid'):
                payload[key] = value
            else:
                result_str = f'\'{key}\' is not a configurable setting for a SNMP v3 host'
                result = {'result_status': 1, 'result_str': result_str} 
                return result 

    elif (action == 'delete'):
        if (session.api_verbose == True):
            print(f'Verbose: Checking to see if SNMP v3 host \'{snmp_host_ip}\' already exists')

        snmp_server_v3_host_list = get_snmp_server_host_snmpv3(session,config_path)

        payload = {
        '_action': 'delete',
        'ipAddress': snmp_host_ip,
        'name': snmp_host_name
        }

        if not snmp_server_v3_host_list:
            result_str = f'SNMP v3 host \'{snmp_host_ip}\' does not exist'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

        else:
            for host in snmp_server_v3_host_list:
                if (host['ipAddress'] == snmp_host_ip):
                    if host.get('portnumber'):
                        payload['portnumber'] = host.get('portnumber')
                    break        
            else:
                result_str = f'SNMP v3 host \'{snmp_host_ip}\' does not exist'
                result = {'result_status': 1, 'result_str': result_str} 
                return result
    
        if (session.api_verbose == True):
            print(f'Verbose: SNMP v3 host \'{snmp_host_ip}\' exists')
    
    post_url = 'configuration/object/snmp_ser_host_snmpv3'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} SNMP v3 host \'{snmp_host_ip}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} SNMP v3 host \'{snmp_host_ip}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} SNMP v3 host \'{snmp_host_ip}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def post_copy_ftp_flash(session, config_path, ftp_host, ftp_user, ftp_password, srcfilename, dstfilename):

    payload = {
        'ftphost': ftp_host,
        'user': ftp_user,
        'passwd': ftp_password,      
        'filename': srcfilename,
        'destfilename': dstfilename
        }

    post_url = 'configuration/object/copy_ftp_flash'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to FTP file \'{srcfilename}\' to flash')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'FTP file \'{srcfilename}\' to flash - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'FTP file \'{srcfilename}\' to flash - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_snmp_server_trap_source(session, config_path):

    get_url = 'configuration/object/snmp_ser_trap_src'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve SNMP trap source')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: SNMP trap source retrieved successfully')
        return response_json['_data']['snmp_ser_trap_src']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve SNMP trap source')
        return None

def post_snmp_server_trap_source(session, config_path, action, snmp_trap_source_ip):
    
    if ( action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
    
    if (action == 'add'):
        
        payload = {
        '_action': 'add',
        'ipaddr': snmp_trap_source_ip
        }
    
    elif (action == 'delete'):

        payload = {
        '_action': 'delete',
        'ipaddr': snmp_trap_source_ip
        }

    post_url = 'configuration/object/snmp_ser_trap_src'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} SNMP trap source as \'{snmp_trap_source_ip}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} SNMP trap source as \'{snmp_trap_source_ip}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} SNMP trap source as \'{snmp_trap_source_ip}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def post_copy_scp_flash(session, config_path, scp_host, scp_username, scp_password, srcfilename, dstfilename):

    payload = {
        'scphost': scp_host,
        'username': scp_username,
        'passwd': scp_password,       
        'filename': srcfilename,
        'destfilename': dstfilename,
        }

    post_url = 'configuration/object/copy_scp_flash'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to SCP copy {scp_host}:/{srcfilename} to flash:/{dstfilename}')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'SCP copy {scp_host}:/{srcfilename} to flash:/{dstfilename} - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'SCP copy {scp_host}:/{srcfilename} to flash:/{dstfilename} - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_clock_set_timezone(session, config_path):

    get_url = 'configuration/object/clock_set_timezone'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve timezone')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: Timezone retrieved successfully')
        return response_json['_data']['clock_set_timezone']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve timezone')
        return None

def post_clock_set_timezone(session, config_path, action, timezone):
    
    if ( action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
    
    if (action == 'add'):
        
        payload = {
        '_action': 'add',
        'name': timezone
        }
    
    elif (action == 'delete'):

        payload = {
        '_action': 'delete'
        }

    post_url = 'configuration/object/clock_set_timezone'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} timezone \'{timezone}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} timezone \'{timezone}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} timezone \'{timezone}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_ntp_server_info(session, config_path):

    get_url = 'configuration/object/ntp_server_info'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve NTP server list')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: NTP server list retrieved successfully')
        return response_json['_data']['ntp_server_info']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve NTP server list')
        return None

def post_ntp_server_info(session, config_path, action, ntp_server_ip, **kwargs):
    
    if ( action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
    
    if (action == 'add'):
        
        payload = {
        '_action': 'add',
        'ip': ntp_server_ip
        }
    
        for key, value in kwargs.items():
            if(key == 'keyid'):
                payload[key] = value
            elif(key == 'iburst'):
                payload[key] = value
            else:
                result_str = f'\'{key}\' is not a configurable setting for a NTP server'
                result = {'result_status': 1, 'result_str': result_str} 
                return result 

    elif (action == 'delete'):
        if (session.api_verbose == True):
            print(f'Verbose: Checking to see if NTP server \'{ntp_server_ip}\' already exists')

        ntp_server_list = get_ntp_server_info(session,config_path)

        payload = {
        '_action': 'delete',
        'ip': ntp_server_ip
        }

        if not ntp_server_list:
            result_str = f'NTP server \'{ntp_server_ip}\' does not exist'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

        else:
            for server in ntp_server_list:
                if (server['ip'] == ntp_server_ip):
                    break        
            else:
                result_str = f'NTP server \'{ntp_server_ip}\' does not exist'
                result = {'result_status': 1, 'result_str': result_str} 
                return result
    
        if (session.api_verbose == True):
            print(f'Verbose: NTP server \'{ntp_server_ip}\' exists')
    
    post_url = 'configuration/object/ntp_server_info'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} NTP server \'{ntp_server_ip}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} NTP server \'{ntp_server_ip}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} NTP server \'{ntp_server_ip}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_snmp_server_trap_enable(session, config_path):

    get_url = 'configuration/object/snmp_ser_trap_enable'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve enabled SNMP trap list')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: Enabled SNMP trap list retrieved successfully')
        return response_json['_data']['snmp_ser_trap_enable']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve enabled SNMP trap list')
        return None

def post_snmp_server_trap_enable(session, config_path, action, snmp_trap_name):
    
    if ( action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
    
    if (action == 'add'):
        
        payload = {
        '_action': 'add',
        'name': snmp_trap_name
        }
    
    elif (action == 'delete'):

        payload = {
        '_action': 'delete',
        'name': snmp_trap_name
        }

    post_url = 'configuration/object/snmp_ser_trap_enable'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} SNMP trap \'{snmp_trap_name}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} SNMP trap \'{snmp_trap_name}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} SNMP trap \'{snmp_trap_name}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def post_copy_scp_system(session, config_path, partition_num, scp_host, scp_user, scp_password, filename):

    payload = {
        'partition_num': partition_num,
        'scphost': scp_host,
        'username': scp_user,
        'filename': filename,
        'passwd': scp_password
        }

    post_url = 'configuration/object/copy_scp_system'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to SCP image to system partition {partition_num}')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'SCP image to system partition {partition_num} - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'SCP image to system partition {partition_num} - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
