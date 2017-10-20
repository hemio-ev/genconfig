#!/usr/bin/python3

from genconfig import *

# simulated data source
data = [
 { 'name': 'test1'
 , 'password': '*'
 , 'uid': 10000
 , 'gid': 10000 },
 { 'name': 'name1'
 , 'password': '*'
 , 'uid': 10001
 , 'gid': 10001 }
]

# write /etc/passwd style file
(
 data
 | add_from_value('gecos', '')
 | add_from_value('shell', '/bin/false')
 | add_from_value('home', '/home/%(name)s') 
 | sort(key=lambda x: x['name'])
 | to_passwd_line()
 > 'passwd.test'
)
