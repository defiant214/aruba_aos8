#!/usr/bin/env python

def get_tacacs_server(session, config_path):
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
    
    if (action != 'add' and action != 'delete' ):
        result_str = f'\'{action}\' is not an acceptable configuration node action'
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

def get_dot1x_auth_profiles(session, config_path):
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

def add_mod_dot1x_auth_profile(session, config_path, profile_name, **kwargs):

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
            

    '''    
   {
  "quiet_period": {
    "qt-period": 0
  },
  "reauth_period": {
    "ra-period": 0
  },
  "use_server_reauth_period": {},
  "use_server_reauth_term_action": {},
  "mkey_period": {
    "mkr-period": 0
  },
  "ukey_period": {
    "ukr-period": 0
  },
  "serverretry_period": {
    "srv-ret-period": 0
  },
  "server_retry": {
    "srv-retries": 0
  },
  "framed_mtu": {
    "fmtu": 0
  },
  "max_requests": {
    "mx-requests": 0
  },
  "reauth_max_requests": {
    "ramx-requests": 0
  },
  "heldstate_bypass_counter": {
    "hs-counter": 0
  },
  "wep_key_retries": {
    "wk-retries": 0
  },
  "wep_key_size": {
    "wk-size": 0
  },
  "wpakey_period_ms": {
    "wk-period": 0
  },
  "wpa2key_delay": {
    "wk-delay": 0
  },
  "wpagkey_delay": {
    "wgk-delay": 0
  },
  "keycache_tmout": {
    "kc-tmout": 0
  },
  "delete_keycache": {},
  "wpa_key_retries": {
    "wpak-retries": 0
  },
  "multicast_keyrotation": {},
  "unicast_keyrotation": {},
  "reauthentication": {},
  "opp_key_caching": {},
  "validate_pmkid": {},
  "use_session_key": {},
  "use_static_key": {},
  "xSec_mtu": {
    "xsecmtu": 0
  },
  "termination_mode": {},
  "termination_eaptype": {
    "eap_t": "eap-tls"
  },
  "termination_innereaptype": {
    "inner_eap_t": "eap-mschapv2"
  },
  "enforce_suite_b_128": {},
  "enforce_suite_b_192": {},
  "enable_token_caching": {},
  "token_caching_period": {
    "tk-cache-period": 0
  },
  "ca_cert": {
    "ca-cert-name": "string"
  },
  "server_cert": {
    "server-cert-name": "string"
  },
  "tls_guest_access": {},
  "tls_guest_role": {
    "tg-role": "string"
  },
  "iesaa": {},
  "eapol_logoff": {},
  "ignore_eap_id_match": {},
  "wpa_fast_handover": {},
  "dot1x_cert_cn_lookup": {},
  "dot1x_auth_profile_clone": {
    "source": "string"
    }
    } 
    
    '''    
    
    
    return

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

def add_mod_aaa_profile(session, config_path, profile_name, **kwargs):
    
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
            result_str = f'{key!r} is not a configurable setting for a AAA profile'
            result = {'result_status': 1, 'result_str': result_str} 
            return result 

    post_url = 'configuration/object/aaa_prof'

    if (session.api_verbose == True):
            print(f'Verbose: Sending POST to \'{session.api_url}{post_url}\' to add/modify AAA profile \'{profile_name}\'')

    response = session.post(post_url, config_path, payload)

    if (response.status_code == 200):
        
        response_json = response.json()
        if (response_json['_global_result']['status'] == 0):
            result_str = 'AAA profile updated successfully'
            result = {'result_status': 0, 'result_str': result_str} 
            return result
        else:
            result_str = 'Unable to update AAA profile'
            result = {'result_status': 1, 'result_str': result_str} 
            return result
    else:
        result_str = 'POST to ' + session.api_url + post_url + ' unsuccessful'
        result = {'result_status': 1, 'result_str': result_str} 
        return result