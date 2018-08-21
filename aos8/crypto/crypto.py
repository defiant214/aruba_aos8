#!/usr/bin/env python

def post_crypto_pki_csr_rsa(session, config_path, key_length, common_name, 
    country, state_prov,  city, organization, unit, email):

    payload = {
        'common_val': common_name,
        'country_val': country,
        'state': state_prov,
        'city_val': city,
        'organization_val': organization,
        'unit_val': unit,
        'email_val': email
        }
    if (key_length == '1024' or key_length == '2048' or key_length == '4096'):
        payload['key_length'] = key_length
    else:
        result_str = f'\'{key_length}\' is not a configurable key length. Please select 1024, 2048, or 4096.'
        result = {'result_status': 1, 'result_str': result_str} 
        return result 
    
    post_url = 'configuration/object/crypto_pki_csr_rsa'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to create RSA CSR')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()

        status_str = response_json['_global_result']['status_str']
        result_str = f'Create RSA CSR - {status_str}'

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

def generate_csr_output(session):

    show_output = session.show_cli_command('show crypto pki csr')

    csr_begin = show_output.get('_data').index('-----BEGIN CERTIFICATE REQUEST-----')

    csr_output = '\n'.join(show_output.get('_data')[csr_begin:])

    return csr_output

def csr_output_to_file(csr_output, filename):
    with open(filename,'w',) as file:
        file.write(csr_output)

def get_crypto_local_pki_cert(session, config_path):

    get_url = 'configuration/object/crypto_local_pki_cert'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve local certificate list')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: Local certificate list retrieved successfully')
        return response_json['_data']['crypto_local_pki_cert']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve local certificate list')
        return None

def post_crypto_local_pki_cert(session, config_path, action, cert_type, cert_name, filename):

    if (action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

    if (action == 'add'):
   
        payload = {
            'cert_type': cert_type,
            'name': cert_name,
            'filename': filename
        }

    elif (action == 'delete'):
        if (session.api_verbose == True):
            print(f'Verbose: Checking to see if certificate \'{cert_name}\' already exists')

        cert_list = get_crypto_local_pki_cert(session,config_path)

        if not cert_list:
            result_str = f'Certificate \'{cert_name}\' does not exist'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

        else:
            for cert in cert_list:
                if (cert['name'] == cert_name):
                    break        
            else:
                result_str = f'Certificate \'{cert_name}\' does not exist'
                result = {'result_status': 1, 'result_str': result_str} 
                return result
    
        if (session.api_verbose == True):
            print(f'Verbose: Certificate \'{cert_name}\' exists')
    

        payload = {
            '_action': 'delete',
            "name": cert_name
        }

    post_url = 'configuration/object/crypto_local_pki_cert'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} local certificate')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()

        status_str = response_json['_global_result']['status_str']
        result_str = f'{action.upper()} local certificate \'{cert_name}\' - {status_str}'
        
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
