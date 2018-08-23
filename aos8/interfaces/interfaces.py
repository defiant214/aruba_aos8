#!/usr/bin/env python

def get_interface_portchannel(session, config_path):
    get_url = 'configuration/object/int_pc'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve port-channel interfaces')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: Port-channel interfaces retrieved successfully')
        return response_json['_data']['int_pc']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrieve port-channel interfaces')
        return None
