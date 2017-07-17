#!/usr/bin/python
# -*- coding: utf-8 -*-

# Configuration generation configuration for kresse

from utils import *
from pipe import *

setup(loglevel=logging.WARN)
#setup(loglevel=logging.DEBUG)

import psycopg2
from psycopg2.extras import RealDictCursor

conn = psycopg2.connect("postgres://carnivora_machine_krill@carnivora.hemio.localhost/carnivora", cursor_factory=RealDictCursor)
cur = conn.cursor() 

cur.execute("""
SELECT *
FROM email.srv_alias()
""")
data_alias = cur.fetchall()

cur.execute("""
SELECT
 l.*,
 ARRAY(
    SELECT address::varchar FROM email.srv_list_subscriber()
        WHERE l.localpart=localpart AND l.domain=domain
 ) AS subscribers
FROM email.srv_list() AS l
""")
data_list = cur.fetchall()

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

cur.execute("""
SELECT DISTINCT domain
FROM email.srv_alias()
UNION
SELECT DISTINCT domain
FROM email.srv_list()
UNION
SELECT DISTINCT domain
FROM email.srv_list_subscriber()
UNION
SELECT DISTINCT domain
FROM email.srv_mailbox()
UNION
SELECT DISTINCT domain
FROM email.srv_redirection()
""")
data_domain = cur.fetchall()

# generate mail configs
# /etc/dovecot/users
# /etc/postfix/maps/generated/mailbox
valid_addresses = []
(
data_mailbox
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
 # passwd requirements
 | add_from_value('home', '/nonexistent')
 | override_from_value('gid', 121)
 | override_from_value('gecos', '')
 | override_from_value('shell', '/bin/false')
 | add_from_key('name', 'address')
   # check and sort out invalid stuff
 | is_valid_crypt('password', methods=[METHOD_SHA512], minsalt=8)
 | is_allowed_uid('uid')
 | is_valid_email('address')
 | info('Valid address')
 | (
    (to_formatted_string('%(address)s') | append_to_list(valid_addresses) ) & # for alias checking
    (to_passwd_line_with_quota()                    > '/etc/dovecot/users') &
    (to_formatted_string('%(address)s %(address)s') > '/etc/postfix/maps/generated/mailbox')
   )
)

# /etc/postfix/maps/generated/relay_domain
# /etc/postfix/maps/generated/relay_domain_self
# /etc/postfix/maps/generated/roleaccount_forced
# /etc/postfix/maps/generated/roleaccount_default
relay_domains = []
FORCED_ABUSE_ADDRESS='abuse@hemio.de'
FORCED_POSTMASTER_ADDRESS='postmaster@hemio.de'
DEFAULT_WEBMASTER_ADDRESS='web@ressort.hemio.de'
(
data_domain
 | sort(cmp_=lambda a, b: cmp(a['domain'], b['domain']))
 # to check the validity of a domain, add the abuse@ address and check that one
 | add_from_value('abuse', 'abuse@%(domain)s')
 | add_from_value('postmaster', 'postmaster@%(domain)s')
 | add_from_value('webmaster', 'webmaster@%(domain)s')
 | is_valid_email('abuse')
 | info('Valid domain')
 | (
     (to_formatted_string('%(domain)s') | append_to_list(relay_domains) ) & # for SRS exclusion list
     (to_formatted_string('%(domain)s OK')
        > '/etc/postfix/maps/generated/relay_domain') &
     (to_formatted_string('%(domain)s %(domain)s')
        > '/etc/postfix/maps/generated/relay_domain_self') &
     (to_formatted_string('%(abuse)s '        + FORCED_ABUSE_ADDRESS +
                          '\n%(postmaster)s ' + FORCED_POSTMASTER_ADDRESS)
        > '/etc/postfix/maps/generated/roleaccount_forced') &
     (to_formatted_string('%(webmaster)s '    + DEFAULT_WEBMASTER_ADDRESS) 
        > '/etc/postfix/maps/generated/roleaccount_default')
   )
)

# /etc/postsrsd.exclude
# HACK because genconfig v1 appends '\n' to chunks when using 'pipe-style' file writing
with open('/etc/postsrsd.exclude.new', 'w') as fd:
    fd.write('SRS_EXCLUDE_DOMAINS=%s\n' % ','.join(relay_domains))

# /etc/postfix/maps/generated/alias
(
data_alias
 | add_from_value('address', '%(localpart)s@%(domain)s')
 | sort(cmp_=lambda a, b: cmp(a['address'], b['address']))
 | add_from_value('mailbox_address', '%(mailbox_localpart)s@%(mailbox_domain)s')
 | is_valid_email('address')
   # Checks if destination in valid_addresses
 | is_valid_dest_address('mailbox_address', valid_addresses)
 | to_formatted_string('%(address)s %(mailbox_address)s')
 > '/etc/postfix/maps/generated/alias'
)

# /etc/postfix/maps/generated/redirection
(
data_redirection
# | is_valid_email('destination')  # destination can be anywhere in the internet - no validation useful
 | add_from_value('source', '%(localpart)s@%(domain)s')
 | sort(cmp_=lambda a, b: cmp(a['source'], b['source']))
 | is_valid_email('source')
 | to_formatted_string('%(source)s %(destination)s')
 > '/etc/postfix/maps/generated/redirection'
)

# special list with all users (all mailbox addresses)
data_list.append({
    'localpart': 'all+users',
    'domain': 'hemio.de',
    'admin': 'postmaster@hemio.de',
    'option': {
               'wonderbolt_keep_headers': True,
               'wonderbolt_overwrite': {'require_sasl_username': ['postmaster@hemio.de']}
              },
    'subscribers': sorted(['{localpart}@{domain}'.format(**xs) for xs in data_mailbox])
})

## Wonderbolt
def wonderbolt_template(x):
    return {
        "envelope_mail_from": "{localpart}+bounce@{domain}".format(**x),
        "envelope_rcpt_to": x["subscribers"],
        "header_add_if_missing": {
            "List-Id":
                "<{localpart}.{domain}>".format(**x),
            "List-Post":
                "<mailto:{localpart}@{domain}>".format(**x),
            "Precedence":
                "list",
            "X-Mailing-List":
                "<{localpart}@{domain}>".format(**x),
        },
        "header_replace": {
            "List-Help":
                "<mailto:{admin}>".format(**x),
            "List-Owner":
                "<mailto:{admin}>".format(**x),
            "List-Subscribe":
                "<mailto:{admin}?body=subscribe%20list%20{localpart}@{domain}>".format(**x),
            "List-Unsubscribe":
                "<mailto:{admin}?body=unsubscribe%20list%20{localpart}@{domain}>".format(**x),
        },
        "hostname": "mail.hemio.de",
        "require_from": x["require_from"],
        "require_sasl_username": x["require_sasl_username"],
        "sasl_recipient_delimiter": "_",
    }

def wonderbolt_list_config(x):
    # defaults
    xs = {
        "require_from": False,
        "require_sasl_username": False,
    }
    xs.update(x)

    d = wonderbolt_template(xs)

    if x["option"].get("wonderbolt_keep_headers"):
        d["header_replace"] = {}
        d["header_add_if_missing"] = {}

    if "wonderbolt_overwrite" in x["option"]:
        d.update(x["option"]["wonderbolt_overwrite"])

    return json.dumps(d, indent=4, sort_keys=True)

# email list configs (wonderbolt)
# /etc/wonderbolt/%(localpart)s@%(domain)s.json
# /etc/postfix/maps/generated/wonderbolt_admins
# /etc/postfix/maps/generated/wonderbolt_transport
wonderbolt_files = []
(
data_list
 | add_from_value('wonderbolt_address', '%(localpart)s@%(domain)s')
 | is_valid_email('wonderbolt_address')
 | info()
 | add_from_function('text', wonderbolt_list_config)
 | (
    write_securely_to_file_template('text', '/etc/wonderbolt/%(wonderbolt_address)s.json') &
    (to_formatted_string('%(wonderbolt_address)s.json') | append_to_list(wonderbolt_files)) &
    (to_formatted_string('%(localpart)s+bounce@%(domain)s %(admin)s')
                  > '/etc/postfix/maps/generated/wonderbolt_admins' ) &
    (to_formatted_string('%(wonderbolt_address)s %(wonderbolt_address)s')
                  > '/etc/postfix/maps/generated/wonderbolt_lists' ) &
    (to_formatted_string('%(wonderbolt_address)s wonderbolt:%(wonderbolt_address)s')
                  > '/etc/postfix/maps/generated/wonderbolt_transport' )
   )
)

# delete superfluous wonderbolt configs
for fname in os.listdir('/etc/wonderbolt/'):
    if not fname.endswith('.json'):
        continue
    if not fname in wonderbolt_files:
        os.unlink(os.path.join('/etc/wonderbolt/', fname))


# Remap stuff (do this last, because now changes will take effect!)
postmap('/etc/postfix/maps/generated/mailbox')
postmap('/etc/postfix/maps/generated/relay_domain')
postmap('/etc/postfix/maps/generated/relay_domain_self')
postmap('/etc/postfix/maps/generated/roleaccount_forced')
postmap('/etc/postfix/maps/generated/roleaccount_default')
postmap('/etc/postfix/maps/generated/alias')
postmap('/etc/postfix/maps/generated/redirection')
postmap('/etc/postfix/maps/generated/wonderbolt_admins')
postmap('/etc/postfix/maps/generated/wonderbolt_transport')
postmap('/etc/postfix/maps/generated/wonderbolt_lists')
os.rename('/etc/postsrsd.exclude.new', '/etc/postsrsd.exclude')

check_call_log(('systemctl', 'reload', 'postfix.service'))
check_call_log(('systemctl', 'reload', 'dovecot.service'))
check_call_log(('systemctl', 'restart', 'postsrsd.service'))

# Writes the new 'backend_status' to the database
conn.commit()

tear_down()

