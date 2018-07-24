#!/usr/bin/env python

def post_crypto_pki_csr_rsa(session, config_path, key_length, common_name, 
    country, state_prov,  city, organization, unit, email):

    payload = {
        'key_val': key_length,
        'common_val': common_name,
        'country_val': country,
        'state': state_prov,
        'city_val': city,
        'organization_val': organization,
        'unit_val': unit,
        'email_val': email
        }

    post_url = 'configuration/object/crypto_pki_csr_rsa'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to create RSA CSR')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'Create RSA CSR - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'Create RSA CSR - FAILED'
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