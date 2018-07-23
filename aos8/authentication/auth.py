#!/usr/bin/env python

def get_tacacs_server(session, config_path):
    '''

    '''
    get_url = 'configuration/object/tacacs_server'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve TACACS server list')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: TACACS server list retrieved successfully')
        return response_json['_data']['tacacs_server']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrive TACACS server')
        return None

def post_tacacs_server(session, config_path, action, tacacs_server_name, **kwargs):
    
    if ( action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result
    
    if (action == 'add'):
        
        payload = {
        '_action': 'add',
        'tacacs_server_name': tacacs_server_name
        }
    
        for key, value in kwargs.items():
            if(key == 'tacacs_host'):
                payload[key] = {'host': value}
            elif(key == 'tacacs_key'):
                payload[key] = {'key': value}
            elif(key == 'tacacs_tcpport'):
                payload[key] = {'tcp-port': value}
            elif(key == 'tacacs_retransmit'):
                payload[key] = {'retransmit': value}
            elif(key == 'tacacs_timeout'):
                payload[key] = {'timeout': value}
            elif(key == 'tacacs_mode'):
                payload[key] = {}
            elif(key == 'tacacs_authorization'):
                payload[key] = {}
            elif(key == 'tac_srcvlan_ip6addr'):
                payload[key] = {'ipv6addr': value['ipv6addr'], 'vlanid': value['vlanid']}
            elif(key == 'tacacs_server_clone'):
                payload[key] = {'source': value}
            else:
                result_str = f'\'{key}\' is not a configurable setting for the TACACS server profile'
                result = {'result_status': 1, 'result_str': result_str} 
                return result 

    elif (action == 'delete'):
        if (session.api_verbose == True):
            print(f'Verbose: Checking to see if TACACS server \'{tacacs_server_name}\' already exists')

        tacacs_server_list = get_tacacs_server(session,config_path)

        if not tacacs_server_list:
            result_str = f'TACACS Server \'{tacacs_server_name}\' does not exist'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

        else:
            for server in tacacs_server_list:
                if (server['tacacs_server_name'] == tacacs_server_name):
                    break        
            else:
                result_str = f'TACACS Server \'{tacacs_server_name}\' does not exist'
                result = {'result_status': 1, 'result_str': result_str} 
                return result
    
        if (session.api_verbose == True):
            print(f'Verbose: TACACS Server \'{tacacs_server_name}\' exists')
    

        payload = {
            '_action': 'delete',
            "tacacs_server_name": tacacs_server_name
        }
    post_url = 'configuration/object/tacacs_server'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} TACACS server \'{tacacs_server_name}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} TACACS server \'{tacacs_server_name}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} TACACS server \'{tacacs_server_name}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_dot1X_auth_profiles(session, config_path):
    get_url = 'configuration/object/dot1x_auth_profile'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve Dot1X auth profile list')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: Dot1X auth profile list retrieved successfully')
        return response_json['_data']['dot1x_auth_profile']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrive Dot1X auth profile list')
        return None

def post_dot1x_auth_profile(session, config_path, action, profile_name, **kwargs):

    if (action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

    if (action == 'add'):

        payload = {
            '_action': 'add',
            'profile-name': profile_name
        } 
    
        for key, value in kwargs.items():
            if(key == 'dot1x_maxf'):
                payload[key] = {'failure-count': value}
            elif(key == 'machine_auth_enf_enable'):
                payload[key] = {}
            elif(key == 'machine_auth_def_role'):
                payload[key] = {'ma-default-role': value}
            elif(key == 'machine_auth_cache_tmout'):
                payload[key] = {'ma-cache-tmout': value}
            elif(key == 'machine_auth_blklist'):
                payload[key] = {}
            elif(key == 'machine_auth_user_def_role'):
                payload[key] = {'ua-default-role': value}
            elif(key == 'idrequest_period'):
                payload[key] = {'idr-period': value}
            elif(key == 'quiet_period'):
                payload[key] = {'qt-period': value}
            elif(key == 'reauth_period'):
                payload[key] = {'ra-period': value}
            elif(key == 'use_server_reauth_period'):
                payload[key] = {}
            elif(key == 'use_server_reauth_term_action'):
                payload[key] = {}
            elif(key == 'mkey_period'):
                payload[key] = {'mkr-period': value}
            elif(key == 'ukey_period'):
                payload[key] = {'ukr-period': value}
            elif(key == 'serverretry_period'):
                payload[key] = {'srv-ret-period': value}
            elif(key == 'server_retry'):
                payload[key] = {'srv-retries': value}
            elif(key == 'framed_mtu'):
                payload[key] = {'fmtu': value}
            elif(key == 'max_requests'):
                payload[key] = {'mx-requests': value}
            elif(key == 'reauth_max_requests'):
                payload[key] = {'ramx-requests': value}
            elif(key == 'heldstate_bypass_counter'):
                payload[key] = {'hs-counter': value}
            elif(key == 'wep_key_retries'):
                payload[key] = {'wk-retries': value}
            elif(key == 'wep_key_size'):
                payload[key] = {'wk-size': value}
            elif(key == 'wpakey_period_ms'):
                payload[key] = {'wk-period': value}
            elif(key == 'wpa2key_delay'):
                payload[key] = {'wk-delay': value}
            elif(key == 'wpagkey_delay'):
                payload[key] = {'wgk-delay': value}
            elif(key == 'keycache_tmout'):
                payload[key] = {'kc-tmout': value}
            elif(key == 'delete_keycache'):
                payload[key] = {}
            elif(key == 'wpa_key_retries'):
                payload[key] = {'wpak-retries': value}
            elif(key == 'multicast_keyrotation'):
                payload[key] = {}
            elif(key == 'unicast_keyrotation'):
                payload[key] = {}
            elif(key == 'reauthentication'):
                payload[key] = {}
            elif(key == 'opp_key_caching'):
                payload[key] = {}
            elif(key == 'validate_pmkid'):
                payload[key] = {}
            elif(key == 'use_session_key'):
                payload[key] = {}
            elif(key == 'use_static_key'):
                payload[key] = {}
            elif(key == 'xSec_mtu'):
                payload[key] = {'xsecmtu': value}
            elif(key == 'termination_mode'):
                payload[key] = {}
            elif(key == 'termination_eaptype'):
                payload[key] = {'eap_t': value}
            elif(key == 'termination_innereaptype'):
                payload[key] = {'inner_eap_t': value}
            elif(key == 'enforce_suite_b_128'):
                payload[key] = {}
            elif(key == 'enforce_suite_b_192'):
                payload[key] = {}
            elif(key == 'enable_token_caching'):
                payload[key] = {}
            elif(key == 'token_caching_period'):
                payload[key] = {'tk-cache-period': value}
            elif(key == 'ca_cert'):
                payload[key] = {'ca-cert-name': value}
            elif(key == 'server_cert'):
                payload[key] = {'server-cert-name': value}
            elif(key == 'tls_guest_access'):
                payload[key] = {}
            elif(key == 'tls_guest_role'):
                payload[key] = {'tg-role': value}
            elif(key == 'iesaa'):
                payload[key] = {}
            elif(key == 'eapol_logoff'):
                payload[key] = {}
            elif(key == 'ignore_eap_id_match'):
                payload[key] = {}
            elif(key == 'wpa_fast_handover'):
                payload[key] = {}
            elif(key == 'dot1x_cert_cn_lookup'):
                payload[key] = {}
            elif(key == 'dot1x_auth_profile_clone'):
                payload[key] = {'source': value}
            else:
                result_str = f'\'{key}\' is not a configurable setting for the Dot1X auth profile'
                result = {'result_status': 1, 'result_str': result_str} 
                return result 

    elif (action == 'delete'):
        if (session.api_verbose == True):
            print(f'Verbose: Checking to see if dot1X auth profile \'{profile_name}\' already exists')

        dot1X_auth_profile_list = get_dot1X_auth_profiles(session,config_path)

        if not dot1X_auth_profile_list:
            result_str = f'dot1X auth profile \'{profile_name}\' does not exist'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

        else:
            for profile in dot1X_auth_profile_list:
                if (profile['profile-name'] == profile_name):
                    break        
            else:
                result_str = f'Dot1X auth profile \'{profile_name}\' does not exist'
                result = {'result_status': 1, 'result_str': result_str} 
                return result
    
        if (session.api_verbose == True):
            print(f'Verbose: Dot1X auth profile \'{profile_name}\' exists')
    

        payload = {
            '_action': 'delete',
            "profile-name": profile_name
        }
    
    post_url = 'configuration/object/dot1x_auth_profile'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} dot1X auth profile \'{profile_name}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} dot1X auth profile \'{profile_name}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} dot1X auth profile \'{profile_name}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_aaa_profiles(session, config_path):
    get_url = 'configuration/object/aaa_prof'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve AAA Profile list')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: AAA Profile list retrieved successfully')
        return response_json['_data']['aaa_prof']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrive AAA Profile list')
        return None

def post_aaa_profile(session, config_path, action, profile_name, **kwargs):
    
    if (action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

    if (action == 'add'):

        payload = {
            '_action': 'add',
            'profile-name': profile_name
        }
    
        for key, value in kwargs.items():
            if(key == 'default_user_role'):
                payload[key] = {'role': value}
            elif(key == 'mac_auth_profile'):
                payload[key] = {'profile-name':value}
            elif(key == 'mac_auth_profile'):
                payload[key] = {'profile-name':value}
            elif(key == 'mac_default_role'):
                payload[key] = {'default-role':value}
            elif(key == 'mba_server_group'):
                payload[key] = {'srv-group':value}
            elif(key == 'dot1x_auth_profile'):
                payload[key] = {'profile-name':value}
            elif(key == 'dot1x_default_role'):
                payload[key] = {'default-role':value}
            elif(key == 'dot1x_server_group'):
                payload[key] = {'srv-group':value}
            elif(key == 'download_role'):
                payload[key] = {}
            elif(key == 'username_from_dhcp_opt12'):
                payload[key] = {}
            elif(key == 'l2_auth_fail_through'):
                payload[key] = {}
            elif(key == 'multiple_server_accounting'):
                payload[key] = {}
            elif(key == 'user_idle_timeout_aaa'):
                payload[key] = {'seconds':value}
            elif(key == 'max_ipv4_for_wireless'):
                payload[key] = {'max_ipv4_users':value}
            elif(key == 'rad_acct_sg'):
                payload[key] = {'server_group_name':value}
            elif(key == 'enable_roaming_rad_acct'):
                payload[key] = {}
            elif(key == 'enable_rad_interim_acct'):
                payload[key] = {}
            elif(key == 'xml_api_client'):
                payload[key] = {'xml_api_server':value}
            elif(key == 'rfc3576_client'):
                payload[key] = {'rfc3576_server':value}
            elif(key == 'udr_group'):
                payload[key] = {'udr_group':value}
            elif(key == 'wwroam'):
                payload[key] = {}
            elif(key == 'devtype_classification'):
                payload[key] = {}
            elif(key == 'enforce_dhcp'):
                payload[key] = {}
            elif(key == 'integrate_pan'):
                payload[key] = {}
            elif(key == 'open_system_rad_acc'):
                payload[key] = {}
            elif(key == 'aaa_prof_clone'):
                payload[key] = {'source':value}
            else:
                result_str = f'\'{key}\' is not a configurable setting for a AAA profile'
                result = {'result_status': 1, 'result_str': result_str} 
                return result 
    elif (action == 'delete'):
        if (session.api_verbose == True):
            print(f'Verbose: Checking to see if aaa profile \'{profile_name}\' already exists')

        aaa_profile_list = get_aaa_profiles(session,config_path)

        if not aaa_profile_list:
            result_str = f'aaa profile \'{profile_name}\' does not exist'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

        else:
            for profile in aaa_profile_list:
                if (profile['profile-name'] == profile_name):
                    break        
            else:
                result_str = f'aaa profile \'{profile_name}\' does not exist'
                result = {'result_status': 1, 'result_str': result_str} 
                return result
    
        if (session.api_verbose == True):
            print(f'Verbose: aaa profile \'{profile_name}\' exists')
    

        payload = {
            '_action': 'delete',
            "profile-name": profile_name
        }

    post_url = 'configuration/object/aaa_prof'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} aaa profile \'{profile_name}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} aaa profile \'{profile_name}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} aaa profile \'{profile_name}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_cp_auth_profiles(session, config_path):
    
    get_url = 'configuration/object/cp_auth_profile'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve captive portal auth profile list')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: Captive portal auth profile list retrieved successfully')
        return response_json['_data']['cp_auth_profile']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrive captive portal auth profile list')
        return None

def post_cp_auth_profile(session, config_path, action, profile_name, **kwargs):
    
    if (action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

    if (action == 'add'):

        payload = {
            '_action': 'add',
            'profile-name': profile_name
        }
    
        for key, value in kwargs.items():
            if(key == 'cp_default_role'):
                payload[key] = {'default-role': value}
            elif(key == 'cp_default_guest_role'):
                payload[key] = {'default-guest-role':value}
            elif(key == 'cp_server_group'):
                payload[key] = {'server-group':value}
            elif(key == 'cp_redirect_pause'):
                payload[key] = {'redirect-pause':value}
            elif(key == 'allow_user'):
                payload[key] = {}
            elif(key == 'allow_guest'):
                payload[key] = {}
            elif(key == 'logout_popup'):
                payload[key] = {}
            elif(key == 'cp_proto_http'):
                payload[key] = {}
            elif(key == 'cp_min_delay'):
                payload[key] = {'minimum-delay':value}
            elif(key == 'cp_max_delay'):
                payload[key] = {'maximum-delay':value}
            elif(key == 'cp_load_thresh'):
                payload[key] = {'cpu-threshold':value}
            elif(key == 'cp_maxf'):
                payload[key] = {'max-authentication-failures':value}
            elif(key == 'cp_show_fqdn'):
                payload[key] = {}
            elif(key == 'authentication_method'):
                payload[key] = {'captive_auth_t':value}
            elif(key == 'cp_login_location'):
                payload[key] = {'login-page':value}
            elif(key == 'cp_welcome_location'):
                payload[key] = {'welcome-page':value}
            elif(key == 'cp_welcome_location_enable'):
                payload[key] = {}
            elif(key == 'proxy'):
                payload[key] = {'address':value.get('address'), 'port':value.get('port')}
            elif(key == 'switch_ip_in_redir_url'):
                payload[key] = {}
            elif(key == 'user_vlan_in_redir_url'):
                payload[key] = {}
            elif(key == 'ip_addr_in_redir_url'):
                payload[key] = {'ip-addr-in-redirection-url':value}
            elif(key == 'single_session'):
                payload[key] = {}
            elif(key == 'cp_white_list'):
                payload[key] = {'white-list':value}
            elif(key == 'cp_black_list'):
                payload[key] = {'black-list':value}
            elif(key == 'show_aup'):
                payload[key] = {}
            elif(key == 'user_idle_timeout_cp'):
                payload[key] = {'seconds':value}
            elif(key == 'cp_redirect_url'):
                payload[key] = {'redirect-url':value}
            elif(key == 'apple_cna_bypass'):
                payload[key] = {}
            elif(key == 'url_hash_key'):
                payload[key] = {'url-hash-key':value}
            elif(key == 'cp_auth_profile_clone'):
                payload[key] = {'source':value}
            else:
                result_str = f'\'{key}\' is not a configurable setting for a captive portal auth profile'
                result = {'result_status': 1, 'result_str': result_str} 
                return result 

    elif (action == 'delete'):
        if (session.api_verbose == True):
            print(f'Verbose: Checking to see if captive portal auth profile \'{profile_name}\' already exists')

        cp_auth_profile_list = get_cp_auth_profiles(session,config_path)

        if not cp_auth_profile_list:
            result_str = f'captive portal auth profile \'{profile_name}\' does not exist'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

        else:
            for profile in cp_auth_profile_list:
                if (profile['profile-name'] == profile_name):
                    break        
            else:
                result_str = f'captive portal auth profile \'{profile_name}\' does not exist'
                result = {'result_status': 1, 'result_str': result_str} 
                return result
    
        if (session.api_verbose == True):
            print(f'Verbose: captive portal auth profile \'{profile_name}\' exists')
    

        payload = {
            '_action': 'delete',
            "profile-name": profile_name
        }

    post_url = 'configuration/object/cp_auth_profile'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} captive portal auth profile \'{profile_name}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} captive portal auth profile \'{profile_name}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} captive portal auth profile \'{profile_name}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_server_group_profiles(session, config_path):
    
    get_url = 'configuration/object/server_group_prof'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve server group profile list')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: Server group profile list retrieved successfully')
        return response_json['_data']['server_group_prof']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrive server group profile list')
        return None

def post_server_group_profile(session, config_path, action, sg_name, **kwargs):
    
    if (action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

    if (action == 'add'):

        payload = {
            '_action': 'add',
            'sg_name': sg_name
        }
    
        for key, value in kwargs.items():
            if(key == 'fail_thru'):
                payload[key] = {}
            elif(key == 'load_balance'):
                payload[key] = {}
            elif(key == 'auth_server'):
                '''
                Value must be list of dicts in following format:
                "auth_server": [{
                    "trim-fqdn": true,
                    "fqdn": "string",
                    "all": true,
                    "operator": "contains",
                    "sub_string": "string",
                    "name": "string",
                    "prio": 0
                }]
                '''
                payload[key] = value.copy()
            elif(key == 'derivation_rules_vlan_role'):
                payload[key] = value.copy()
            elif(key == 'server_group_prof_clone'):
                payload[key] = {'source':value}
            else:
                result_str = f'\'{key}\' is not a configurable setting for a server group profile'
                result = {'result_status': 1, 'result_str': result_str} 
                return result 

    elif (action == 'delete'):
        if (session.api_verbose == True):
            print(f'Verbose: Checking to see if server group profile \'{sg_name}\' already exists')

        server_group_profile_list = get_server_group_profiles(session,config_path)

        if not server_group_profile_list:
            result_str = f'server group profile \'{sg_name}\' does not exist'
            result = {'result_status': 1, 'result_str': result_str} 
            return result

        else:
            for profile in server_group_profile_list:
                if (profile['sg_name'] == sg_name):
                    break        
            else:
                result_str = f'server group profile \'{sg_name}\' does not exist'
                result = {'result_status': 1, 'result_str': result_str} 
                return result
    
        if (session.api_verbose == True):
            print(f'Verbose: server group profile \'{sg_name}\' exists')
    

        payload = {
            '_action': 'delete',
            'sg_name': sg_name
        }

    post_url = 'configuration/object/server_group_prof'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} server group profile \'{sg_name}\'')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} server group profile \'{sg_name}\' - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} server group profile \'{sg_name}\' - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_tacacs_accounting(session, config_path):
    
    get_url = 'configuration/object/tacacs_acc'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve TACACS account configuration')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: TACACS account configuration retrieved successfully')
        return response_json['_data']['tacacs_acc']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrive TACACS account configuration')
        return None

def post_tacacs_accounting(session, config_path, action, **kwargs):
    
    if (action != 'add' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

    if (action == 'add'):

        payload = {
            '_action': 'add',
        }
    
        for key, value in kwargs.items():
            if(key == 'tacacs_acc__sg'):
                payload[key] = {'sg': value}
            elif(key == 'tacacs_acc__cfg'):
                payload[key] = {}
            elif(key == 'tacacs_acc__action'):
                payload[key] = {}
            elif(key == 'tacacs_acc__show'):
                payload[key] = {}
            elif(key == 'tacacs_acc__all'):
                payload[key] = {}
            else:
                result_str = f'\'{key}\' is not a configurable setting for TACACS accounting'
                result = {'result_status': 1, 'result_str': result_str} 
                return result 

    post_url = 'configuration/object/tacacs_acc'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} TACACS accounting configuration')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} TACACS accounting configuration - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} TACACS accounting configuration - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

def get_radius_nas_ip(session, config_path):
    
    get_url = 'configuration/object/rad_nas_ip'

    if (session.api_verbose == True):
        print(f'Verbose: Sending GET to \'{session.api_url}{get_url}\' to retrieve RADIUS NAS IP address')
    
    response = session.get(get_url, config_path)

    if (response.status_code == 200):
        response_json = response.json()
        if (session.api_verbose == True):
                print('Verbose: RADIUS NAS IP address retrieved successfully')
        return response_json['_data']['rad_nas_ip']
    
    else:
        if (session.api_verbose == True):
                print('Verbose: Unable to retrive RADIUS NAS IP address')
        return None

def post_radius_nas_ip(session, config_path, action, **kwargs):
    
    if (action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable API action'
        result = {'result_status': 1, 'result_str': result_str} 
        return result

    if (action == 'add'):

        payload = {
            '_action': 'add'
        }

        for key, value in kwargs.items():
            if(key == 'nasip'):
                payload[key] = value
                break
            elif(key == 'nasvlan'):
                payload[key] = value
                break
            else:
                result_str = f'\'{key}\' is not a configurable setting for RADIUS NAS IP address'
                result = {'result_status': 1, 'result_str': result_str} 
                return result

    elif (action == 'delete'):
        payload = {
            '_action': 'delete'
        }

    post_url = 'configuration/object/rad_nas_ip'

    if (session.api_verbose == True):
        print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to {action} RADIUS NAS IP address')
    
    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        
        if (response_json['_global_result']['status'] == 0):
            result_str = f'{action.upper()} RADIUS NAS IP address - SUCCESS'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = f'{action.upper()} RADIUS NAS IP address - FAILED'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = f'POST to \'{session.api_url}{post_url}\' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result