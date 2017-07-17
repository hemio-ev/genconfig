#!/usr/bin/python
# -*- coding: utf-8 -*-

# Configuration generation configuration for pumpe

from utils import *
from pipe import *

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

print("# data_alias")
print((data_alias[0]))

print("# data_list")
print((data_list[0]))

print("# data_list_subscriber")
print((data_list_subscriber[0]))

print("# data_mailbox")
print((data_mailbox[0]))

print("# data_redirection")
print((data_redirection[0]))

#conn.commit()

