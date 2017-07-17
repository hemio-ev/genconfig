#!/usr/bin/python
# -*- coding: utf-8 -*-

# Configuration generation configuration for pumpe

from utils import *
from pipe import *

import psycopg2
from psycopg2.extras import RealDictCursor
import os.path

import openssl_utils

conn = psycopg2.connect("postgres://carnivora_machine_flunder@carnivora.hemio.localhost/carnivora", cursor_factory=RealDictCursor)
cur = conn.cursor()

cur.execute('''
SELECT domain, port, https, "user", subservice, option,
    array_to_string(ARRAY(SELECT CAST(a.domain AS varchar) FROM web.srv_alias() AS a WHERE a.site = s.domain AND a.site_port = s.port),\' \') AS aliases
FROM web.srv_site() AS s
''')
data_web = cur.fetchall()

cur.execute('SELECT uid, COALESCE(password, \'x\') AS password, "user" as name, subservice AS protocol FROM server_access.srv_user()')
data_usr = cur.fetchall()

cur.execute("SELECT identifier, domain, port, x509_request, x509_certificate, x509_chain FROM web.srv_https()")
data_x509 = cur.fetchall()

dir_certs = '/etc/apache2/ssl/'

for https in data_x509:
    name = "{0}-{1}_{2}".format(https["domain"], https["port"], https["identifier"])

    # private key
    file_key = os.path.join(dir_certs, name + ".key")
    # certificate signing request (csr)
    file_csr = os.path.join(dir_certs, name + ".csr")
    # certificate (from database)
    file_crt = os.path.join(dir_certs, name + ".crt")

    file_abstract = os.path.join(dir_certs, name)
   
    # create new key, if key file is missing
    # always create new certificate request (csr) if new key is created
    if not os.path.isfile(file_key):
        openssl_utils.keygen(file_key)
        openssl_utils.certgen(file_key, file_csr, https["domain"], 730)

    # if certificate in database present write to file
    if https["x509_certificate"] is not None:
        with open(file_crt, "w") as f:
            # also add the intermediate certificates (chain)
            certs = [https["x509_certificate"]] + https["x509_chain"]
            certs_formatted = list(map(openssl_utils.format_csr, certs))

            f.write("\n\n".join(certs_formatted))

    if not os.path.isfile(file_crt):
        print(file_crt)
        openssl_utils.self_sign(file_abstract)

    # if certificate request (csr) present write to database
    if os.path.isfile(file_csr):
        with open(file_csr, "r") as f:
            text = f.read()
            cert_raw = openssl_utils.extract_csr(text)
            cur.execute(
                "SELECT web.fwd_x509_request("
                "p_domain := %s, p_port := %s, p_identifier := %s, p_x509_request := %s)",
                (https["domain"], https["port"], https["identifier"], cert_raw)
            )

# generate shell configs
# /etc/passwd
# /etc/shadow
missing_homes = []
missing_cgi_dirs = []
missing_cgi_phps = []
missing_logs = []
(
    data_usr
    # check if it is usefull for anything
    | is_allowed_uid('uid')
    #| is_valid_crypt_ssha512('password')
    # set things that can be globally applied
    | add_from_value('gecos', '') 
    | add_from_value('administrator_list', [])
    | add_from_value('group_password', 'x')
    | add_from_value('shell', '/bin/bash')
    | add_from_value('home', '/home/%(name)s')
    | add_from_value('log_dir', '%(home)s/logs')
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
            where(lambda x: not os.path.isdir(x['log_dir']))
            | add_from_key('dirname', 'log_dir')
            | add_from_value('permissions', 0o770)
            | add_from_key('owner', 'name')
            | add_from_key('group', 'name_web')
            | append_to_list(missing_logs)
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
missing_logs | makedirs()

(
    missing_cgi_phps
    |
    (
        write_php_cgi()
        & chown()
        & chmod()
    )
)    


# das hier macht web hosts
missing_dirs = []
(   
 data_web
 | add_from_value('web_dir', '/home/%(user)s/%(domain)s-%(port)d')
 | add_from_value('user_cgi', '%(user)s--cgi')
 | add_from_value('user_web', '%(user)s--web')
 | add_from_value('home', '/home/%(user)s')
 # set config values
 | add_from_value('DocumentRoot', '%(web_dir)s/html')
 # produce results
 |
 (
     # list DocumentRoots that do not exist
    (
        # example.org
        add_from_key('dirname', 'web_dir')
        | where(lambda x: x['subservice'] != 'http_redirect')
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
        | where(lambda x: x['subservice'] != 'http_redirect')
        | where(lambda x: not os.path.isdir(x['dirname']))
        | add_from_value('permissions', 0o2755)
        | add_from_key('owner', 'user')
        | add_from_key('group', 'user_web')
        | append_to_list(missing_dirs)
    )
    & (to_apache2_vhost() > '/etc/apache2/sites-available/5-generated.conf')
   )
)

missing_dirs | makedirs()

# reload apache2
check_call_log(('systemctl', 'reload', 'apache2.service'))

conn.commit()

