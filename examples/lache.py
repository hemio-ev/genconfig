#!/usr/bin/python
# -*- coding: utf-8 -*-

# Configuration generation configuration for pumpe

from utils import *
from pipe import *

setup(loglevel=logging.WARN)

conn = mysql.connect(
    host = 'winde.colormove.de',
    db = 'kurbel',
    user = 'machine_lache',
    ssl = {
        'key': '/etc/genconfig/lache.colormove.de_2011_MySQL-Client_06.key',
        'cert': '/etc/genconfig/lache.colormove.de_2011_MySQL-Client_06.crt',
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
    missing_homes | make_home_dirs(permissions=0o750)


if pending(conn, 'backend_web_pending') or once_daily():
    # das hier macht web hosts
    missing_dirs = []
    (
     from_db_procedure(conn, 'backend_web_accounts')
       # set config values
     | add_from_key('ServerName', 'web_vhost')
     | add_from_key('ServerAlias', 'server_alias')
     | add_from_value('DocumentRoot', '/home/%(user)s/%(web_vhost)s')
     | add_from_key('php_admin_value open_basedir', 'DocumentRoot')
       # produce results
     | (
         # list DocumentRoots that do not exist
        (where(lambda x: not os.path.isdir(x['DocumentRoot'])) | append_to_list(missing_dirs)) &
         # write apache config
        (to_apache2_vhost() > '/etc/apache2/sites-available/5-sites')
       )
    )

    for missing_dir in missing_dirs:
        os.makedirs(missing_dir['DocumentRoot'], 0o750)
        os.chown(missing_dir['DocumentRoot'], pwd.getpwnam(missing_dir['user']).pw_uid, grp.getgrnam('www-data').gr_gid)
        os.chown(os.path.dirname(missing_dir['DocumentRoot']), -1, grp.getgrnam('www-data').gr_gid)

    # reload apache2
    check_call_log(('service', 'apache2', 'reload'))

tear_down()
