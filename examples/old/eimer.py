#!/usr/bin/python
# -*- coding: utf-8 -*-

# Configuration generation configuration for eimer

from utils import *
from pipe import *

setup()

conn = mysql.connect(
    host = 'winde.colormove.de',
    db = 'kurbel',
    user = 'machine_eimer',
    ssl = { 
        'key': '/etc/genconfig/eimer.colormove.de_2011_MySQL-Client_0D.key',
        'cert': '/etc/genconfig/eimer.colormove.de_2011_MySQL-Client_0D.crt',
        'ca': '/etc/ssl/certs/Colormove_Root_CA.pem',
        'capath': None,
        'cipher': None,
        }   
    )   

if pending(conn, 'backend_shell_pending') or once_daily():
    # generate shell configs
    # /etc/passwd
    # /etc/shadow
    missing_homes = []
    (   
     from_db_procedure(conn, 'backend_shell_accounts')
       # convert the database format to something we can use
       # for passwd and shadow
     | add_from_key('gid', 'uid')
     | add_from_value('home', '/home/%(name)s')
     | add_from_value('gecos', '') 
       # for group and gshadow
     | add_from_key('group_name', 'name')
     | add_from_value('member_list', [])
     | add_from_value('administrator_list', [])
     | add_from_value('group_password', 'x')
       # check and sort out invalid stuff
     | is_valid_crypt_ssha512('password')
     | is_allowed_uid('uid')
     | ( 
        (where(lambda x: not os.path.isdir(x['home'])) | append_to_list(missing_homes)) &
        (inject_system_passwd() | override_from_value('password', 'x') | to_passwd_line() > '/etc/passwd') &
        (inject_system_shadow() | to_shadow_line() > '/etc/shadow') &
        (inject_system_group() | to_group_line() > '/etc/group') &
        (inject_system_gshadow() | to_gshadow_line() > '/etc/gshadow')
       )   
    )   

    # create missing home dirs
    missing_homes | make_home_dirs(permissions=0o770)

if pending(conn, 'backend_jabber_pending') or once_daily():
    # generate jabber auth file and domain file
    # /etc/prosody/users
    # /etc/prosody/conf.avail/managed_domains.cfg.lua
    (
     from_db_procedure(conn, 'backend_jabber_accounts')
     | is_valid_crypt_ssha512('password_hash')
     | add_from_value('test_email', '%(node)s@%(domain)s')
     | is_valid_email('test_email')
     | (
        (to_formatted_string('VirtualHost "%(domain)s"') | unique() > '/etc/prosody/conf.avail/managed_domains.cfg.lua' ) &
        (to_formatted_string('%(node)s:%(domain)s:%(password_hash)s') > '/etc/prosody/users' )
       )
    )
    
    check_call_log(('service', 'prosody', 'reload'))


tear_down()

