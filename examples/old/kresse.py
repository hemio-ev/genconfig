#!/usr/bin/python
# -*- coding: utf-8 -*-

# Configuration generation configuration for kresse

from utils import *
from pipe import *

setup(loglevel=logging.WARN)

conn = mysql.connect(
    host = 'winde.colormove.de',
    db = 'kurbel',
    user = 'machine_kresse',
    ssl = {
        'key': '/etc/genconfig/kresse.colormove.de_2011_MySQL-Client_04.key',
        'cert': '/etc/genconfig/kresse.colormove.de_2011_MySQL-Client_04.crt',
        'ca': '/etc/ssl/certs/Colormove_Root_CA.pem',
        'capath': None,
        'cipher': None,
        }
    )

if pending(conn, 'backend_mail_pending') or once_daily():
    # generate mail configs
    # >= is the selinuxy version of >
    # /etc/passwd
    # /etc/shadow
    # /etc/dovecot/passwd.virtual_mail_users
    # /etc/postfix/maps/virtual_mailbox_users
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
     | add_from_value('home', '/var/mail/%(domain)s/%(user)s')
     | override_from_value('gid', 111)
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
        (where(lambda x: not os.path.isdir(x['home'])) | append_to_list(missing_homes)) &
        (inject_system_passwd() | override_from_value('password', 'x') | to_passwd_line() >= '/etc/passwd') &
        (inject_system_shadow() | override_from_value('password', '*') | to_shadow_line() >= '/etc/shadow') &
        (to_passwd_line_with_quota()                    >= '/etc/dovecot/passwd.virtual_mail_users') &
        (to_formatted_string('%(address)s %(address)s') >= '/etc/postfix/maps/virtual_mailbox_users')
       )
    )

    # Make home dirs
    # First, we need to make sure the domain dirs exist.
    SELINUX_MAILHOME_CONTEXT = 'system_u:object_r:mail_spool_t:s0'
    for missing_home in missing_homes:
        domain_path = os.path.split(missing_home['home'])[0]
        if not os.path.isdir(domain_path): # /var/mail/domain doesn't exist
            os.mkdir(domain_path, 0o750)
            os.chown(domain_path, 0, 111)
            chcon(domain_path, SELINUX_MAILHOME_CONTEXT)

    missing_homes | make_home_dirs(permissions=0o700, 
                                   selinux_context=SELINUX_MAILHOME_CONTEXT,
                                   skel='/etc/mailskel')

    # /etc/postfix/maps/virtual_mailbox_domains
    # /etc/postfix/maps/virtual_mailbox_roleaccounts_forced
    # /etc/postfix/maps/virtual_mailbox_roleaccounts_default
    FORCED_ABUSE_ADDRESS='abuse@mail.hemio.de'
    FORCED_POSTMASTER_ADDRESS='postmaster@hemio.de'
    DEFAULT_WEBMASTER_ADDRESS='root@pumpe.colormove.de'
    (
     from_db_procedure(conn, 'backend_mail_domains')
       # to check the validity of a domain, add the abuse@ address and check that one
     | add_from_value('abuse', 'abuse@%(domain)s')
     | add_from_value('postmaster', 'postmaster@%(domain)s')
     | add_from_value('webmaster', 'webmaster@%(domain)s')
     | is_valid_email('abuse')
     | info('Valid domain')
     | (
         (to_formatted_string('%(domain)s OK') >= '/etc/postfix/maps/virtual_mailbox_domains') &
         (to_formatted_string('%(abuse)s '        + FORCED_ABUSE_ADDRESS +
                              '\n%(postmaster)s ' + FORCED_POSTMASTER_ADDRESS)
            >= '/etc/postfix/maps/virtual_mailbox_roleaccounts_forced') &
         (to_formatted_string('%(webmaster)s '    + DEFAULT_WEBMASTER_ADDRESS) 
            >= '/etc/postfix/maps/virtual_mailbox_roleaccounts_default')
       )
    )

    # /etc/postfix/maps/virtual_mailbox_aliases
    (
     from_db_procedure(conn, 'backend_mail_aliases')
     | is_valid_email('address')
     | is_valid_dest_address('dest_address', valid_addresses) # Checks if destination in valid_addresses
     | to_formatted_string('%(address)s %(dest_address)s') >= '/etc/postfix/maps/virtual_mailbox_aliases'
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
             ) | cat() >= '/etc/mlmilter/hcf/%s.hcf' % mailing_list
            

        # special list with all users
        mailing_list_members.append(
            {'list_address': 'all_users_use_in_bcc_only@hemio.de',
             'members': ', '.join(valid_addresses)})

        mailing_list_members | to_formatted_string('%(list_address)s %(members)s') >= '/etc/postfix/maps/virtual_mailbox_mailing_lists'
        

    # Remap stuff (do this last, because now changes will take effect!)
    postmap('/etc/postfix/maps/virtual_mailbox_users')
    postmap('/etc/postfix/maps/virtual_mailbox_domains')
    postmap('/etc/postfix/maps/virtual_mailbox_aliases')
    postmap('/etc/postfix/maps/virtual_mailbox_mailing_lists')
    postmap('/etc/postfix/maps/virtual_mailbox_roleaccounts_forced')
    postmap('/etc/postfix/maps/virtual_mailbox_roleaccounts_default')
    check_call_log(('service', 'postfix', 'reload'))
    check_call_log(('service', 'dovecot', 'reload'))

tear_down()