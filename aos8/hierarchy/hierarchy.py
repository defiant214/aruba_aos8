#!/usr/bin/env python

def get_node_hierarchy(session):
    get_url = 'configuration/object/node_hierarchy'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve node hierarchy')
    
    # Send GET to API Session
    get_response_json = session.get(get_url)

    # Successful GET for node hierarchy
    if (get_response_json.status_code == 200):
        # Parse JSON response to GET
        get_response = get_response_json.json()
        if (session.api_verbose == True):
                print('Verbose: Node hierarchy retrieved successfully')
        return get_response
    # Unsuccessful GET for node hierarchy
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrive node hierarchy')
        return None

def parse_node_hierarchy(node_hierarchy):
    
    node_list = []
    
    for node_level1 in node_hierarchy['childnodes']:
        node_path_1 = '/' + node_level1['name']

        if node_level1['childnodes']:
            for node_level2 in node_level1['childnodes']:
                node_path_2 = node_path_1 + '/' + node_level2['name']
      
                if node_level2['childnodes']:
                    for node_level3 in node_level2['childnodes']:
                        node_path_3 = node_path_2 + '/' + node_level3['name']

                        if node_level3['childnodes']:
                            for node_level4 in node_level3['childnodes']:
                                node_path_4 = node_path_3 + '/' + node_level4['name']

                                if node_level4['childnodes']:
                                    for node_level5 in node_level4['childnodes']:
                                        node_path_5 = node_path_4 + '/' + node_level5['name']                                      
                                        node_list.append(
                                            {
                                                'config_path': node_path_5, 'controllers': node_level5['devices']
                                            }
                                        )
                                
                                node_list.append(
                                    {
                                        'config_path': node_path_4, 'controllers': node_level4['devices']
                                    }
                                )
                                       
                        node_list.append(
                            {
                                'config_path': node_path_3, 'controllers': node_level3['devices']
                            }
                        )

                node_list.append(
                    {
                        'config_path': node_path_2, 'controllers': node_level2['devices']
                    }
                )
        node_list.append(
            {
                'config_path': node_path_1, 'controllers': node_level1['devices']
            }
        )
            
    return node_list

def check_if_node_exists(config_path, parsed_node_hierarchy):
    
    for node in parsed_node_hierarchy:
        if (node.get('config_path') == config_path):
            return True
    
    return False

def post_configuration_node(session, node_path, action):
    
    # Only allow Add or Delete API action
    if (action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
    
    # Check to see if node already exists
    node_hierarchy = get_node_hierarchy(session)
    parsed_node_hierarchy = parse_node_hierarchy(node_hierarchy)

    if (session.api_verbose == True):
        print(f'Verbose: Checking to see if node \'{node_path}\' already exists')
    
    if (action == 'add'):
        
        if check_if_node_exists(node_path,parsed_node_hierarchy):
            result_str = f'Node \'{node_path}\' already exists!'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    
        if (session.api_verbose == True):
            print(f'Verbose: Node \'{node_path}\' does not already exist')

        payload = {'_action': 'add', 'node-path': node_path}

    elif (action == 'delete'):
        if not check_if_node_exists(node_path,parsed_node_hierarchy):
            result_str = f'Node \'{node_path}\' does not exist!'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    
        if (session.api_verbose == True):
            print(f'Verbose: Node \'{node_path}\' exists')

        payload = {'_action': 'delete', 'node-path': node_path}    
    
    post_url = 'configuration/object/configuration_node'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} node \'{node_path}\'')
    
    # Send POST to API Session
    response = session.post(post_url, '/md', payload)

    if (response.status_code == 200):
        response_json = response.json()
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} node \'{node_path}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} node \'{node_path}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result 

def check_if_device_exists(mac_address, parsed_node_hierarchy):
    
    for node in parsed_node_hierarchy:
        if node.get('controllers'):
            for controller in node['controllers']:
                if (controller.get('mac') == mac_address):
                    return True
    
    return False

def post_configuration_device(session, node_path, action, device_model, mac_address):
    
    if (action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
    
    node_hierarchy = get_node_hierarchy(session)
    parsed_node_hierarchy = parse_node_hierarchy(node_hierarchy)
    
    if (session.api_verbose == True):
        print(f'Verbose: Checking to see if device with MAC address \'{mac_address}\' already exists')

    if (action == 'add'):
        if check_if_device_exists(mac_address,parsed_node_hierarchy):
            result_str = f'Device with MAC address \'{mac_address}\' already exists!'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    
        if (session.api_verbose == True):
            print(f'Verbose: Device with MAC address \'{mac_address}\' does not already exist')

        payload = {'_action': 'add', 'config-path': node_path, 'dev-model': device_model, 'mac-address': mac_address}

    elif (action == 'delete'):
        if not check_if_device_exists(mac_address,parsed_node_hierarchy):
            result_str = f'Device with MAC address \'{mac_address}\' does not exist!'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    
        if (session.api_verbose == True):
            print(f'Verbose: Device with MAC address \'{mac_address}\' exists')
    
        payload = {'_action': 'delete', 'config-path': node_path, 'dev-model': device_model, 'mac-address': mac_address}

    post_url = 'configuration/object/configuration_device'
    
    if (session.api_verbose == True):
            print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} a' 
            f'\'{device_model}\' device with MAC address \'{mac_address}\' to node \'{node_path}\''
            )
    response = session.post(post_url, '/md', payload)
    
    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} device \'{mac_address}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} device \'{mac_address}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result 
