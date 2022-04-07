#!/usr/bin/env python3
'''
firewall Address set up using FORTIOSAPI from Github
https://github.com/fortinet-solutions-cse/fortiosapi
'''


import logging, sys
from fortiosapi import FortiOSAPI
from dotenv import dotenv_values
from datetime import datetime as dt


formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger    = logging.getLogger('fortiosapi')
hdlr      = logging.FileHandler('testfortiosapi.log')

hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

dv = dotenv_values('.env')



## =============================== FUNCTIONS ================================ ##
def fgt_login(FGT, TKN):
    '''
    Login
    '''
    try:
        ip = dv['BASE']
    except:
        ip = input('Enter FGT IP or DNS: ')

    ## Login with Token (Removed all user/pswd code)
    try:
        FGT.tokenlogin(ip, TKN)
        print('Token login success')
        return True
    except:
        raise Exception(f'\nToken login failed - Invalid token: {TKN}')


def select_group():
    name_127 = 'GRP_Malicious'
    name_938 = 'Block_SSLVPN'

    resp = input(f'     Enter 127 for {name_127}, or 938 for {name_938}: ')

    if int(resp) == 127:
        return int(resp), name_127
    elif int(resp) == 938:
        return int(resp), name_938
    else:
        raise Exception('Invalid entry')


def get_new_address_info(SELECTION):
    if SELECTION == 127:
        pre = 'Mal_'
    elif SELECTION == 938:
        pre = 'MalSSLVPN_'

    ip_prompt = 'IPv4 Address (/32 will be appended automatically)'
    ip1 = input(f'  Enter {ip_prompt}: ')
    ip2 = input(f'Confirm {ip_prompt}: ')

    if ip1 != ip2:
        raise Exception(f'Failed to confirm IPv4 address\n1: {ip1}\n2: {ip2}')

    data_name    = f'{pre}{ip2}'
    data_comment = f'Programmatically created on: {dt.now()}'

    data = {
        'name': data_name,
        'subnet': f'{ip2}/32',
        'type': 'ipmask',
        'associated_interface': "port31",
        'comment': data_comment,
        'color': '7'
    }

    return data_name, data


def create_address_object(FGT, DATA):
    try:
        main_address_set = FGT.set(path='firewall', name='address', data=DATA, vdom=dv['VDOM'])
        print(f"FGT_ADDRESS_SET: {main_address_set['http_status']} - {main_address_set['status']}")
    except:
        print(main_address_set)
        print("new address object creation failed - exiting")
        sys.exit(1)
    

def prep_addrgrp_members(FGT, NEW_MEMBER, ADDRGRP_NAME):
    resp_addrgrp_get = FGT.get(path='firewall', name='addrgrp', mkey=ADDRGRP_NAME, vdom=dv['VDOM'])
    addrgrp_members  = resp_addrgrp_get['results'][0]['member']

    new_member = {
        'name': NEW_MEMBER
    }

    addrgrp_members.append(new_member)

    payload_addrgrp_members = {
        'member': addrgrp_members
    }

    return ADDRGRP_NAME, payload_addrgrp_members


def get_addrgroup(FGT, ADDRGRP_NAME):
    try:
        main_addrgrp_get = FGT.get(path='firewall', name='addrgrp', mkey=ADDRGRP_NAME, vdom=dv['VDOM'])
        main_addrgrp_lst = main_addrgrp_get['results'][0]['member']
        print(f'\n{ADDRGRP_NAME} Members: ')
        for mem in main_addrgrp_lst:
            print(f"  - {mem['name']}")
    except:
        print(main_addrgrp_get)


def set_addrgroup(FGT, ADDRGRP_NAME, DATA):
    try:
        main_addrgrp_set = FGT.set(path='firewall', name='addrgrp', mkey=ADDRGRP_NAME, data=DATA, vdom=dv['VDOM'])
        print(f"FGT_ADDRGRP_SET: {main_addrgrp_set['http_status']} - {main_addrgrp_set['status']}")
    except:
        print(main_addrgrp_set)


def fgt_logout(FGT):
    try:
        FGT.logout()
        print(f'\nLogged out successfully')
    except Exception as e:
        print(f'\nFailed to log out successfully: {e}')


def main():
    ## Instantiate FortiOSAPI
    fgt = FortiOSAPI()

    ## LOGIN
    fgt_login(FGT=fgt, TKN=tkn)

    ## Select Address Group
    SEL, ADDRGRP = select_group()

    ## Get Address Info
    address_name, payload_address = get_new_address_info(SELECTION=SEL)

    ## Get Address Group Info
    addrgrp_name, payload_addrgrp_members = prep_addrgrp_members(FGT=fgt, NEW_MEMBER=address_name, ADDRGRP_NAME=ADDRGRP)

    ## CREATE NEW ADDRESS OBJECT
    create_address_object(FGT=fgt, DATA=payload_address)

    ## UPDATE ADDRESS GROUP MEMBERS
    set_addrgroup(FGT=fgt, ADDRGRP_NAME=addrgrp_name, DATA=payload_addrgrp_members)

    ## Get (Updated) Address Group Members
    get_addrgroup(FGT=fgt, ADDRGRP_NAME=addrgrp_name)

    ## Logout
    fgt_logout(FGT=fgt)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nReceived KeyboardInterrupt')
        sys.exit(1)
    except Exception as e:
        print(f'\nUnexpected Exception: {e}')
        sys.exit(1)
