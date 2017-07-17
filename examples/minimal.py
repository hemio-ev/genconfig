#!/usr/bin/env python3

from genconfig import *

dev_mode('/tmp/genconfig_test', wipe=True)

# simulated data source
data = [
 { 'name': 'test1'
 , 'uid': 10000
 , 'gid': 10000 }
]

# write /etc/passwd style file
(
 data
 | add_from_value('gecos', '')
 | add_from_value('shell', '/bin/false')
 | add_from_value('home', '/home/%(name)s')
 | inject_system_passwd()
 | add_from_value('password', '*')
 | to_passwd_line()
 > '/etc/passwd.test'
)

check_call_log(('systemctl', 'reload', 'apache2.service'))
