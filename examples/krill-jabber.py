#!/usr/bin/python
# -*- coding: utf-8 -*-

# Configuration generation configuration for eimer

from utils import *
from pipe import *

import psycopg2
from psycopg2.extras import RealDictCursor

setup(loglevel=logging.WARN)

conn = psycopg2.connect("postgres://carnivora_machine_krill@carnivora.hemio.localhost/carnivora?sslmode=require", cursor_factory=RealDictCursor)
cur = conn.cursor()

cur.execute("""
SELECT *
FROM jabber.srv_account()
""")
data = cur.fetchall()

# generate jabber auth file and domain file
# /etc/prosody/users
# /etc/prosody/conf.avail/managed_domains.cfg.lua
(
 data
 | is_valid_crypt('password', methods=[METHOD_SHA512], minsalt=8)
 | add_from_value('test_email', '%(node)s@%(domain)s')
 | is_valid_email('test_email')
 | sort(cmp_=lambda a, b: cmp(a['test_email'], b['test_email']))
 | (
    (to_formatted_string('VirtualHost "%(domain)s"') | unique() > '/etc/prosody/conf.avail/managed_domains.cfg.lua.generated-but-UNUSED' ) &
    (to_formatted_string('%(node)s:%(domain)s:%(password)s') > '/etc/prosody/users' )
   )
)

check_call_log(('systemctl', 'reload', 'prosody.service'))

# Writes the new 'backend_status' to the database
conn.commit()

tear_down()

