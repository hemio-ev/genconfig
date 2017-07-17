#!/usr/bin/python
# -*- coding: utf-8 -*-

# Configuration generation configuration for plankton

from utils import *
from pipe import *

setup(loglevel=logging.WARN)
#setup(loglevel=logging.DEBUG)

import psycopg2
from psycopg2.extras import RealDictCursor

conn = psycopg2.connect("postgres://carnivora_machine_plankton@carnivora.hemio.localhost/carnivora", cursor_factory=RealDictCursor)
cur = conn.cursor() 

# generate mail configs
# /etc/dovecot/users
# /etc/passwd
# /etc/shadow
missing_homes = []
cur.execute("""
SELECT *
FROM email.srv_mailbox()
""")
(
cur.fetchall()
  # Add the postmaster email user - this should always be present and not
  # depend on the database, thus adding it by hand.
  # using a uid 90000<uid<100000 assures that no clashes occur.
  # password for postmaster is 'EkMitMkbSMuvZhoU'
 | inject_mail_address(localpart='postmaster', domain='hemio.de',
                       password='$6$GnbRMOYa$Rq9hblgc7akxORNLgEkYlUdXf5LtIRCCRk2PRsbGkibtZ6FhsPwz3B30Z86LjcaJoqpgquRVnx/TgioX/9afA.',
                       uid=90001)
 | sort(cmp_=lambda a, b: cmp(a['uid'], b['uid']))
 # address
 | add_from_value('address', '%(localpart)s@%(domain)s')
 | add_from_key('name', 'address')
 # passwd requirements
 | add_from_value('home', '/var/mail/%(domain)s/%(localpart)s')
 | override_from_value('gid', 119)
 | override_from_value('gecos', '')
 | override_from_value('shell', '/bin/false')
   # check and sort out invalid stuff
 | is_valid_crypt('password', methods=[METHOD_SHA512], minsalt=8)
 | is_allowed_uid('uid')
 | is_valid_email('address')
 | info('Valid address')
 | (
     (to_passwd_line_with_quota()
       > '/etc/dovecot/users') &
     (inject_system_passwd() | override_from_value('password', 'x') | to_passwd_line()
       > '/etc/passwd') &
     (inject_system_shadow() | override_from_value('password', '*') | to_shadow_line()
       > '/etc/shadow') &
     (where(lambda x: not os.path.isdir(x['home'])) | append_to_list(missing_homes))
   )
)

# make missing home dirs
# first the domain part
for missing_home in missing_homes:
    domain_path = '/var/mail/%(domain)s' % missing_home
    if not os.path.isdir(domain_path):
        os.mkdir(domain_path, 0o750)
        os.chown(domain_path, 0, 119)

# now the missing home dirs themselves
missing_homes | make_home_dirs(permissions=0o700, skel='/etc/mailskel')


check_call_log(('systemctl', 'reload', 'dovecot'))

# Writes the new 'backend_status' to the database
conn.commit()

tear_down()
