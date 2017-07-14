#!/usr/bin/python
# -*- coding: utf-8 -*-

from genconfig import *

# simulated data source
data = [
 { 'name': 'test1'
 , 'password': '*'
 , 'uid': 10000
 , 'gid': 10000 }
]

# write /etc/passwd style file
(
 data
 | add_from_value('gecos', '')
 | add_from_value('shell', '/bin/false')
 | add_from_value('home', '/home/%(name)s') 
 | to_passwd_line()
 > 'passwd.test'
)
