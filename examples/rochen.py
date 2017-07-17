#!/usr/bin/python
# -*- coding: utf-8 -*-

# Configuration generation configuration for pumpe

from utils import *
from pipe import *

setup(loglevel=logging.WARN)

conn = mysql.connect(
    host = 'hummer.colormove.local',
    db = 'kurbel',
    user = 'machine_rochen',
    ssl = { 
        'key': '/etc/genconfig/rochen.colormove.local_2013_Genconf_4.key',
        'cert': '/etc/genconfig/rochen.colormove.local_2013_Genconf_4.crt',
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
    missing_cgi_dirs = []
    missing_cgi_phps = []
    (
        from_db_procedure(conn, 'backend_shell_accounts')
        # check if it is usefull for anything
        | is_allowed_uid('uid')
        | is_valid_crypt_ssha512('password')
        # set things that can be globally applied
        | add_from_value('gecos', '') 
        | add_from_value('administrator_list', [])
        | add_from_value('group_password', 'x')
        | add_from_value('home', '/home/%(name)s')
        | add_from_key('name_default', 'name')
        | add_from_value('name_cgi', '%(name)s--cgi')
        | add_from_value('name_web', '%(name)s--web')
        # multiply
        |
        (
            (
                where(lambda x: not os.path.isdir(x['home']))
                | append_to_list(missing_homes)
            )
            &
            (
                # /var/www/sgi/user--cgi
                add_from_value('dirname', '/var/www/cgi/%(name_cgi)s')
                | where(lambda x: not os.path.isdir(x['dirname']))
                | add_from_value('permissions', 0o555)
                | add_from_key('owner', 'name_cgi')
                | add_from_key('group', 'name_cgi')
                | append_to_list(missing_cgi_dirs)
            )
            &
            (
                # /var/www/sgi/user--cgi/php
                add_from_value('filepath', '/var/www/cgi/%(name_cgi)s/php')
                | where(lambda x: not os.path.isfile(x['filepath']))
                | add_from_value('permissions', 0o500)
                | add_from_key('owner', 'name_cgi')
                | add_from_key('group', 'name_cgi')
                | append_to_list(missing_cgi_phps)
            )
            &
            (
                multiply_chunk(
                    # DEFAULT user and group
                    add_from_key('gid', 'uid')
                    | add_from_key('group_name', 'name')
                    | add_from_value('member_list', [])
                    ,
                    # CGI user and group
                    override_from_function('uid', lambda x: x['uid'] + 100000)
                    | override_from_key('name', 'name_cgi')
                    | override_from_value('password', 'x')
                    | override_from_value('shell', '/usr/sbin/nologin')
                    | add_from_key('gid', 'uid')
                    | add_from_key('group_name', 'name')
                    | add_from_function('member_list', lambda x: [ x['name_default'] ])
                    ,
                    # WEB user and group - we don't need the user...
                    override_from_function('uid', lambda x: x['uid'] + 200000)
                    | override_from_key('name', 'name_web')
                    | override_from_value('password', 'x')
                    | override_from_value('shell', '/usr/sbin/nologin')
                    | add_from_key('gid', 'uid')
                    | add_from_key('group_name', 'name')
                    | add_from_function('member_list', lambda x: [ x['name_default'], x['name_cgi'], 'www-data' ])
                )
                |
                (
                    # sinks
                    ( inject_system_passwd() | override_from_value('password', 'x') | to_passwd_line() > '/etc/passwd' )
                    & ( inject_system_shadow() | to_shadow_line() > '/etc/shadow' )
                    & ( inject_system_group() | to_group_line() > '/etc/group' )
                    & ( inject_system_gshadow() | to_gshadow_line() > '/etc/gshadow' )
                )
            )
        )
    )

    # create missing home dirs
    missing_homes | override_from_function('gid', lambda x: grp.getgrnam(x['name'] + '--web').gr_gid) | make_home_dirs(permissions=0o710)
    missing_cgi_dirs | makedirs()

    (
        missing_cgi_phps
        |
        (
            write_php_cgi()
            & chown()
            & chmod()
        )
    )    


if pending(conn, 'backend_web_pending') or once_daily():
    # das hier macht web hosts
    missing_dirs = []
    (   
     from_db_procedure(conn, 'backend_web_accounts')
     | add_from_value('web_dir', '/home/%(user)s/%(web_vhost)s')
     | add_from_value('user_cgi', '%(user)s--cgi')
     | add_from_value('user_web', '%(user)s--web')
     # set config values
     | add_from_key('ServerName', 'web_vhost')
     | add_from_key('ServerAlias', 'server_alias')
     | add_from_value('DocumentRoot', '%(web_dir)s/htdocs')
     | add_from_value('Options', '+ExecCGI')
     | add_from_value('SuexecUserGroup', '%(user_cgi)s %(user_cgi)s')
     | add_from_value('FcgidWrapper', '/var/www/cgi/%(user)s--cgi/php .php')
     # produce results
     |
     (
         # list DocumentRoots that do not exist
        (
            # example.org
            add_from_key('dirname', 'web_dir')
            | where(lambda x: not os.path.isdir(x['dirname']))
            | add_from_value('permissions', 0o2751)
            | add_from_key('owner', 'user') 
            | add_from_key('group', 'user_cgi') 
            | append_to_list(missing_dirs)
        )
        &
        (
            # example.org/htodcs
            add_from_key('dirname', 'DocumentRoot')
            | where(lambda x: not os.path.isdir(x['dirname']))
            | add_from_value('permissions', 0o2755)
            | add_from_key('owner', 'user')
            | add_from_key('group', 'user_web')
            | append_to_list(missing_dirs)
        )
        & (to_apache2_vhost() > '/etc/apache2/sites-available/5-sites')
       )
    )

    missing_dirs | makedirs()

    # reload apache2
    check_call_log(('systemctl', 'reload', 'apache2.service'))

tear_down()

