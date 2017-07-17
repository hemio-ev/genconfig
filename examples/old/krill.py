#!/usr/bin/python
# -*- coding: utf-8 -*-

# Configuration generation configuration for kresse

from utils import *
from pipe import *

setup(loglevel=logging.WARN)

import psycopg2
from psycopg2.extras import RealDictCursor

conn = psycopg2.connect("postgres://carnivora_machine_krill@carnivora.hemio.localhost/carnivora?connect_timeout=5", cursor_factory=RealDictCursor)
cur = conn.cursor() 

cur.execute("""
SELECT *
FROM email.srv_alias()
""")
data_alias = cur.fetchall()

cur.execute("""
SELECT *
FROM email.srv_list()
""")
data_list = cur.fetchall()

cur.execute("""
SELECT *
FROM email.srv_list_subscriber()
""")
data_list_subscriber = cur.fetchall()

cur.execute("""
SELECT *
FROM email.srv_mailbox()
""")
data_mailbox = cur.fetchall()

cur.execute("""
SELECT *
FROM email.srv_redirection()
""")
data_redirection = cur.fetchall()

if pending(conn, 'backend_mail_pending') or once_daily():
    # generate mail configs
    # /etc/dovecot/passwd
    # /etc/postfix/maps/generated/users
    valid_addresses = []
    missing_homes = []
    ( 
     from_db_procedure(conn, 'backend_mail_accounts')
       # Add the postmaster email user - this should always be present and not
       # depend on the database, thus adding it by hand.
       # using a uid 90000<uid<100000 assures that no clashes occur.
       # password for postmaster is 'EkMitMkbSMuvZhoU'
     | inject_mail_address(address='postmaster@hemio.de',
                           password_hash='$6$GnbRMOYa$Rq9hblgc7akxORNLgEkYlUdXf5LtIRCCRk2PRsbGkibtZ6FhsPwz3B30Z86LjcaJoqpgquRVnx/TgioX/9afA.',
                           uid=90001)
       # convert the database format to something we can use
     | add_from_function('user',   lambda x: get_localpart_from_emailaddr(x['address']))
     | add_from_function('domain', lambda x: get_domain_from_emailaddr(x['address']))
     | add_from_value('home', '/nonexistent')
     | override_from_value('gid', 121)
     | override_from_value('gecos', '')
     | override_from_value('shell', '/bin/false')
     | add_from_key('name', 'address')
     | add_from_key('password', 'password_hash')
       # check and sort out invalid stuff
     | is_valid_crypt_ssha512('password')
     | is_allowed_uid('uid')
     | is_valid_email('address')
     | info('Valid address')
     | (
        (to_formatted_string('%(address)s') | append_to_list(valid_addresses) ) & # for alias checking
        (to_passwd_line_with_quota()                    > '/etc/dovecot/passwd') &
        (to_formatted_string('%(address)s %(address)s') > '/etc/postfix/maps/generated/users')
       )
    )
    # /etc/postfix/maps/generated/relay_domains
    # /etc/postfix/maps/generated/roleaccounts_forced
    # /etc/postfix/maps/generated/roleaccounts_default
    FORCED_ABUSE_ADDRESS='abuse@hemio.de'
    FORCED_POSTMASTER_ADDRESS='postmaster@hemio.de'
    DEFAULT_WEBMASTER_ADDRESS='root@rochen.colormove.de'
    (
     from_db_procedure(conn, 'backend_mail_domains')
       # to check the validity of a domain, add the abuse@ address and check that one
     | add_from_value('abuse', 'abuse@%(domain)s')
     | add_from_value('postmaster', 'postmaster@%(domain)s')
     | add_from_value('webmaster', 'webmaster@%(domain)s')
     | is_valid_email('abuse')
     | info('Valid domain')
     | (
         (to_formatted_string('%(domain)s OK') > '/etc/postfix/maps/generated/relay_domains') &
         (to_formatted_string('%(abuse)s '        + FORCED_ABUSE_ADDRESS +
                              '\n%(postmaster)s ' + FORCED_POSTMASTER_ADDRESS)
            > '/etc/postfix/maps/generated/roleaccounts_forced') &
         (to_formatted_string('%(webmaster)s '    + DEFAULT_WEBMASTER_ADDRESS) 
            > '/etc/postfix/maps/generated/roleaccounts_default')
       )
    )

    # /etc/postfix/maps/generated/aliases
    (
     from_db_procedure(conn, 'backend_mail_aliases')
     | is_valid_email('address')
     | is_valid_dest_address('dest_address', valid_addresses) # Checks if destination in valid_addresses
     | to_formatted_string('%(address)s %(dest_address)s') > '/etc/postfix/maps/generated/aliases'
    )

    # Make mailing lists
    mailing_lists = []
    pending_mailing_lists = []
    (
     from_db_procedure(conn, 'backend_mail_lists')
     | (
        (to_formatted_string('%(list_address)s') | append_to_list(mailing_lists)) &
        (where(lambda x: x['pending']) | to_formatted_string('%(list_address)s') | append_to_list(pending_mailing_lists))
       )
    )

    if pending_mailing_lists or once_daily():
        mailing_list_members = []
        for mailing_list in mailing_lists:
            members = []
            (
             from_db_procedure(conn, 'backend_mail_list_members', (mailing_list, ))
             | to_formatted_string('%(member_address)s')
             | append_to_list(members)
            )
            mailing_list_members.append(
                {'list_address': mailing_list,
                 'members': ', '.join(members)})

            ('<%s>' % mailing_list,
             'List-ID: <%s>' % mailing_list.replace('@', '.'),
             'List-Help: <mailto:postmaster@hemio.de>',
             'List-Unsubscribe: <mailto:postmaster@hemio.de?body=unsubscribe%%20list%%20%s>'
                % mailing_list,
             'List-Subscribe: <mailto:postmaster@hemio.de?body=subscribe%%20list%%20%s>'
                % mailing_list,
             'List-Post: <mailto:%s>' % mailing_list,
             'Precedence: list',
             'X-Mailing-List: <%s>' % mailing_list,
             ) | cat() > '/etc/mlmilter/hcf/%s.hcf' % mailing_list
            

        # special list with all users
        mailing_list_members.append(
            {'list_address': 'all_users_use_in_bcc_only@hemio.de',
             'members': ', '.join(valid_addresses)})

        mailing_list_members | to_formatted_string('%(list_address)s %(members)s') > '/etc/postfix/maps/generated/mailing_lists'
        

    # Remap stuff (do this last, because now changes will take effect!)
    postmap('/etc/postfix/maps/generated/users')
    postmap('/etc/postfix/maps/generated/relay_domains')
    postmap('/etc/postfix/maps/generated/aliases')
    postmap('/etc/postfix/maps/generated/mailing_lists')
    postmap('/etc/postfix/maps/generated/roleaccounts_forced')
    postmap('/etc/postfix/maps/generated/roleaccounts_default')
    check_call_log(('systemctl', 'reload', 'postfix.service'))
    check_call_log(('systemctl', 'reload', 'dovecot.service'))

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

    check_call_log(('systemctl', 'reload', 'prosody.service'))

tear_down()
