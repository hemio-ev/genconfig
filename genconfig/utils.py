#!/usr/bin/python
# -*- coding: utf-8
"""Useful utilities for genconfig"""

__license__ = """
## License ##    
# Copyright (C) 2011 Mika Pflüger <mika@mikapflueger.de>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.                                      
#                                                                      
# This program is distributed in the hope that it will be useful, but  
# WITHOUT ANY WARRANTY to the extent permittet by applicable law; without
# even the implied warranty of           
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU    
# General Public License for more details. (See COPYING)               
#                                                                      
# You should have received a copy of the GNU General Public License    
# along with this program.  If not, see <http://www.gnu.org/licenses/> 
#
# This product includes software developed by the OpenSSL Project
# for use in the OpenSSL Toolkit. (http://www.openssl.org/)
#
# * In addition, as a special exception, the copyright holders give
# * permission to link the code of portions of this program with the
# * OpenSSL library under certain conditions as described in each
# * individual source file, and distribute linked combinations
# * including the two.
# * You must obey the GNU General Public License in all respects
# * for all of the code used other than OpenSSL.  If you modify
# * file(s) with this exception, you may extend this exception to your
# * version of the file(s), but you are not obligated to do so.  If you
# * do not wish to do so, delete this exception statement from your
# * version.  If you delete this exception statement from all source
# * files in the program, then also delete it here.
##"""

## Changelog ##
# Please see the changelog in the main module.
##

# Standard python modules
import sys
import os
import logging
import errno
import subprocess
import shutil
import shlex
import json
import types
import fcntl
import itertools
import pwd
import grp
import spwd
import crypt
from collections import namedtuple as _namedtuple
import datetime
import cPickle as pickle

from . import base
from . import filters

# log in the general namespace
logger = logging.getLogger('genconfig')
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(levelname)-8s %(message)s'))
logger.addHandler(handler)

## Pipe objects

#class from_db_procedure(base.Producer, mysql.cursors.DictCursor):
#    """An automatically closing, generating cursor to be used on stored
#    procedures.
#
#    Usage:
#    
#    with from_db_procedure(conn, 'backend_shell_accounts', ('eimer',)) as db:
#        for row in db:
#            #do something
#
#    or simply as a producer in a pipe:
#    from_db_procedure(conn, 'backend_shell_accounts', ('eimer',)) | concat()
#    """
#    def __init__(self, connection, procedure, arguments=[]):
#        mysql.cursors.DictCursor.__init__(self, connection)
#        base.Producer.__init__(self)
#        self._procedure = procedure
#        self._arguments = arguments
#
#    def __enter__(self):
#        self.callproc(self._procedure, self._arguments)
#        return self
#
#    def next(self):
#        row = self.fetchone()
#        if row is None:
#            raise StopIteration
#        return row
#
#    def __exit__(self, type_=None, value=None, traceback=None):
#        self.close()
#
#class from_db_query(base.Producer, mysql.cursors.DictCursor):
#    """An automatically closing, generating cursor to execute arbitrary SQL commands.
#    Usage like from_db_procedure."""
#    def __init__(self, connection, query, args=None):
#        mysql.cursors.DictCursor.__init__(self, connection)
#        base.Producer.__init__(self)
#        self._query = query
#        self._args = args
#        self._conn = connection
#    
#    def __enter__(self):
#        self.execute(self._query, self._args)
#        if self._conn.show_warnings():
#            raise Exception('MySQLdb is stupid and suppresses this error: %s' % 
#                            str(self._conn.show_warnings()))
#        return self
#
#    def next(self):
#        row = self.fetchone()
#        if row is None:
#            raise StopIteration
#        return row
#
#    def __exit__(self, type_=None, value=None, traceback=None):
#        self.close()

class inject_system_passwd(base.Filter):
    """Injects system users into the pipe stream."""
    def __enter__(self):
        self._syspwd = []
        for pwd_entry in pwd.getpwall():
            if pwd_entry.pw_uid < MIN_UID or pwd_entry.pw_uid == 65534: # system or nobody
                self._syspwd.append(pwd_entry)
        return self

    def next(self):
        if self._syspwd:
            pwd_struct = self._syspwd.pop(0)
            chunk = {
                'name': pwd_struct.pw_name,
                'passwd': pwd_struct.pw_name,
                'uid': pwd_struct.pw_uid,
                'gid': pwd_struct.pw_gid,
                'gecos': pwd_struct.pw_gecos,
                'home': pwd_struct.pw_dir,
                'shell': pwd_struct.pw_shell
                }
        else:
            chunk = self._chunk
        return chunk

class inject_mail_address(base.Filter):
    """Injects given mail address into the pipe stream."""
    def __init__(self, localpart, domain, password, uid, quota=None):
        base.Filter.__init__(self)
        self._dict = {'quota': quota,
                       'password': password,
                       'uid': uid,
                       'localpart': localpart,
                       'domain': domain}
        self._injected = False

    def next(self):
        if not self._injected:
            chunk = self._dict
            self._injected = True
        else:
            chunk = self._chunk
        return chunk

class inject_system_shadow(base.Filter):
    """Injects system users shadow dicts into the pipe stream."""
    def __enter__(self):
        self._sysspwd = []
        for spwd_entry in spwd.getspall():
            uid = pwd.getpwnam(spwd_entry.sp_nam).pw_uid
            if uid < MIN_UID or uid == 65534: # system or nobody
                self._sysspwd.append(spwd_entry)
        return self

    def next(self):
        if self._sysspwd:
            spwd_struct = self._sysspwd.pop(0)
            chunk = {
                'name': spwd_struct.sp_nam,
                'password': spwd_struct.sp_pwd,
                'lastchange': spwd_struct.sp_lstchg,
                'minage': spwd_struct.sp_min,
                'maxage': spwd_struct.sp_max,
                'warning_period': spwd_struct.sp_warn,
                'inact_period': spwd_struct.sp_inact,
                'expire_date': spwd_struct.sp_expire,
                'reserved': spwd_struct.sp_flag
                }
        else:
            chunk = self._chunk
        return chunk


class inject_system_group(base.Filter):
    """Injects system groups into the pipe stream."""
    def __enter__(self):
        self._sysgrp = []
        for grp_entry in grp.getgrall():
            gid = grp_entry.gr_gid
            if gid < MIN_UID or gid == 65534: # system or nobody
                self._sysgrp.append(grp_entry)
        return self

    def next(self):
        if self._sysgrp:
            grp_struct = self._sysgrp.pop(0)
            chunk = {
                'group_name': grp_struct.gr_name,
                'group_password': 'x',
                'gid': grp_struct.gr_gid,
                'member_list': grp_struct.gr_mem
                }
        else:
            chunk = self._chunk
        return chunk

class inject_system_gshadow(base.Filter):
    """Injects system gshadow entries into the pipe stream."""
    def __enter__(self):
        self._sysgrp = []
        for grp_entry in grp.getgrall():
            gid = grp_entry.gr_gid
            if gid < MIN_UID or gid == 65534: # system or nobody
                self._sysgrp.append(grp_entry)
        return self

    def next(self):
        if self._sysgrp:
            grp_struct = self._sysgrp.pop(0)
            chunk = {
                'group_name': grp_struct.gr_name,
                'group_password': grp_struct.gr_passwd,
                'administrator_list': [],
                'member_list': grp_struct.gr_mem
                }
        else:
            chunk = self._chunk
        return chunk

class makedirs(base.Sink):
    """Make directories passed in. Expects a dictionary with the keys:
    'dirname': the directory to create
    'owner': the owner of the new dir
    'group': the group of the new dir
    'permissions': the permissions to apply (default if not available: 0o750)
    'selinux_context': 'the selinux context to apply (default: None)"""
    #TODO: race
    def send(self, chunk):
        dirname = chunk['dirname']
        owner = chunk['owner']
        group = chunk['group']
        permissions = chunk.get('permissions', 0o750)
        selinux_context = chunk.get('selinux_context', None)
        os.mkdir(dirname, permissions)
        os.chown(dirname, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid)
        os.chmod(dirname, permissions)
        if selinux_context is not None:
            chcon(chunk['home'], self._selinux_context)

class chown(base.Sink):
    """chown chunk['filepath'] to chunk['owner'] and chunk['group']"""
    def send(self, chunk):
        filepath = chunk['filepath']
        owner = chunk['owner']
        group = chunk['group']
        os.chown(filepath, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid)        

class chmod(base.Sink):
    """chmod chunk['filepath'] to chunk['permissions']"""
    def send(self, chunk):
        filepath = chunk['filepath']
        permissions = chunk['permissions']
        os.chmod(filepath, permissions)

class write_php_cgi(base.Sink):
    """creates the bash script that starts php and is usually called by cgi"""
    def send(self, chunk):
        filepath = chunk['filepath']
        with open(filepath, 'w') as f:
            f.write('#!/bin/bash\nexec /usr/lib/cgi-bin/php5')
            f.close

class make_home_dirs(base.Sink):
    """Makes any home dirs passed in. Given permissions, selinux_context
    and/or a skeleton directory, will apply them."""
    def __init__(self, permissions=0o750, skel='/etc/skel', selinux_context=None):
        base.Sink.__init__(self)
        self._permissions = permissions
        self._skel = skel
        self._selinux_context = selinux_context

    def send(self, chunk):
        os.mkdir(chunk['home'], self._permissions)
        os.chown(chunk['home'], chunk['uid'], chunk['gid'])
        if self._selinux_context is not None:
            chcon(chunk['home'], self._selinux_context)
        if self._skel is not None:
            copytree_with_ids(chunk['home'], self._skel, chunk['uid'], chunk['gid'])


def pending(conn, query):
    cursor = conn.cursor()
    cursor.execute("SELECT %s()" % query)
    if conn.show_warnings():
        raise Exception('MySQLdb is stupid and suppresses this error: %s' % 
                        str(conn.show_warnings()))
    
    result = cursor.fetchall()[0][0]
    cursor.close()
    return result

## Time-Keeping functions
class Once(object):
    """True only once in the given time interval. Do not instantiante directly, you
    have to keep every Once instance with a given timedelta unique!"""
    def __init__(self, timedelta):
        microseconds = (timedelta.days*24*60*60 + timedelta.seconds) * 1000 * 1000 + timedelta.microseconds
        filename = '/var/lib/genconfig/timestamp_%d' % microseconds
        try:
            with open(filename) as fd:
                lasttime = pickle.load(fd)
        except IOError:
            logger.warning('No database for timedelta %s found, using 1.1.1970' % timedelta)
            lasttime = datetime.datetime.fromtimestamp(0)
        now = datetime.datetime.now()
        self._truth = (now - lasttime) >= timedelta
        if self._truth:
            with open(filename, 'w') as fd:
                pickle.dump(now, fd)
        
    def __call__(self):
        return self

    def __nonzero__(self):
        return self._truth

once_weekly = Once(datetime.timedelta(7))
once_daily = Once(datetime.timedelta(1))
once_hourly = Once(datetime.timedelta(0, 60*60))

## subprocess Communication
check_call = subprocess.check_call
call = subprocess.call

def check_call_log(args,
                   bufsize=0,
                   executable=None,
                   preexec_fn=None,
                   close_fds=False,
                   shell=False,
                   cwd=None,
                   env=None,
                   universal_newlines=False,
                   startupinfo=None,
                   creationflags=0,
                   logging_func=logger.debug):
    """Behaves like subprocess.check_call, but you cannot
    reroute the childs stdin and stdout, instead stdin and
    stdout will be logged with the given logging_func (default priority:
    logging.debug) so that you don't have to worry about the programm
    giving output."""
    subp = subprocess.Popen(args,
                            bufsize=bufsize,
                            executable=executable,
                            preexec_fn=preexec_fn,
                            close_fds=close_fds,
                            shell=shell,
                            cwd=cwd,
                            env=env,
                            universal_newlines=universal_newlines,
                            startupinfo=startupinfo,
                            creationflags=creationflags,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout, stderr = subp.communicate()
    if stdout or subp.returncode:
        logging_func("%s:out:%s", args, stdout)
    if stderr or subp.returncode:
        logging_func("%s:err:%s", args, stderr)
    if subp.returncode:
        raise subprocess.CalledProcessError(subp.returncode, args)
    

## Permission handling and file i/o
def copytree_with_ids(src, dst,
                      uid, gid):
    """Copy a directory tree from srcname to destname,
    both must exist already.
    Sets uid and gid."""
    for file_ in os.listdir(src):
        srcname = os.path.join(src, file_)
        dstname = os.path.join(dst, file_)
        if os.path.isdir(srcname):
            shutil.copy2(srcname, dstname)
            os.chown(dstname, uid, gid)
            copytree_with_ids(srcname, dstname, uid, gid)
        else:
            shutil.copy2(srcname, dstname)
            os.chown(dstname, uid, gid)


# Check functions
class is_simple_unix_username(filters.CheckLog):
    """Usernames should only contain Alphanumerics and -"""
    _log_string = 'User is invalid: '

    def _testing_function(self, username):
        if not username.replace('-', '').isalnum():
            return False
        return True


# from python3.4 stdlib crypt.py
class _Method(_namedtuple('_Method', ['name', 'ident', 'salt_chars', 'total_size'])):
    """Class representing a salt method per the Modular Crypt Format or the
    legacy 2-character crypt method."""

    def __repr__(self):
        return '<METHOD_{}>'.format(self.name)

#  available salting/crypto methods
METHOD_CRYPT = _Method('CRYPT', None, 2, 13)
METHOD_MD5 = _Method('MD5', '1', 8, 34)
METHOD_SHA256 = _Method('SHA256', '5', 16, 63)
METHOD_SHA512 = _Method('SHA512', '6', 16, 106)

crypt_methods = {METHOD_CRYPT, METHOD_MD5, METHOD_SHA256, METHOD_SHA512}


class is_valid_crypt(filters.CheckLog):
    """Checks if the password is a valid crypt(3)-formatted password hash using only the given extended glibc methods.
    Classic DES is not supported.
    methods defaults to (METHOD_SHA256, METHOD_SHA512) and needs to be an iterable of members of crypt_methods.
    If minsalt is not None, a minimum of minsalt characters salt is enforced."""
    def __init__(self, key, methods=(METHOD_SHA256, METHOD_SHA512), minsalt=None,
               loglevel=logging.WARN, log_string="Invalid crypt(3) hash: "):
        filters.CheckLog.__init__(self, key)
        self._log_string = log_string
        self._loglevel = loglevel
        self.methods = {method.ident: method for method in methods}
        self.minsalt = minsalt

    def _testing_function(self, hash_):
        # ensure basic format
        if not hash_.startswith('$'):
            return False
        try:
            id_, salt, encrypted = hash_[1:].split('$')
        except ValueError:
            return False
        if not salt.replace('/', '').replace('.', '').isalnum():
            return False
        if not encrypted.replace('/', '').replace('.', '').isalnum():
            return False

        # check method
        try:
            method = self.methods[id_]
        except KeyError:
            return False

        if self.minsalt is not None:
            if len(salt) < self.minsalt:
                return False
            if len(salt) > method.salt_chars:
                return False

        if len(hash_) > method.total_size:
            return False

        return True


MIN_UID = 90000
class is_allowed_uid(filters.CheckLog):
    """Checks if the uid is over MIN_UID and under the debian limit of
    4294967295"""
    _log_string = 'uid invalid: '

    def _testing_function(self, uid):
        if uid < MIN_UID or uid > 4294967294:
            return False
        return True

class is_valid_email(filters.CheckLog):
    """Checks for the validity of an email.
    Only checks if the address is valid for internal use, so if it is allowed
    at our site."""
    _log_string = 'invalid email: '

    def _testing_function(self, addr):
        # Check maximal length
        if len(addr) > 254: 
            return False
        # Check for number of @s, split into local and domain part.
        if addr.count('@') != 1: 
            return False
        local = get_localpart_from_emailaddr(addr)
        domain = get_domain_from_emailaddr(addr)

        if not _is_valid_localpart(local):
            return False

        # Check domain validity
        # Check maximal individual length
        if len(domain) > 253:
            return False
        # Check minimum length
        if len(domain) < 3:
            return False
        # We don't check that all chunks are len(chunk) < 64. Whatever.
        if '' in domain.split('.') or domain.count('.') < 1:
            return False
        if domain.split('-')[-1] == '' or domain.split('-')[0] == '':
            return False
        if not domain.replace('.', '').replace('-', '').isalnum():
            return False
        if domain.endswith('mail.hemio.de'):
            return False
        return True

def _is_valid_localpart(local):
    # Check maximal individual length
    if len(local) > 64:
        return False
    # Check minimum length
    if len(local) < 1:
        return False
    # Check for illegal double or leading/trailing dots
    if '' in local.split('.'):
        return False
    # Remove legal characters from local part
    # actually rfc-legal: '!#$%&'*+-/=?^_`{|}~'
    for i in '.-+':
        local = local.replace(i, '')
    # No uppercase allowed
    if local.lower() != local:
        return False
    return local.isalnum()

class is_valid_localpart(filters.CheckLog):
    """Checks for the validity of a localpart.
    Only checks for validity at our site, so if it is allowed here for us, not if it is rfc-legal."""
    _log_string = 'invalid localpart: '

    def _testing_funciton(self, local):
        return _is_valid_localpart(local)

class is_in_list(filters.CheckLog):
    """Checks if value behind key is in given list."""
    def __init__(self, key, list_):
        filters.CheckLog.__init__(self, key)
        self._list = list_
        self._log_string = 'Not in list %s: ' % str(list_)

    def _testing_function(self, value):
        return value in self._list

class is_valid_dest_address(is_in_list):
    """Checks if destination address is in a given set of addresses."""
    _log_string = 'invalid destination address: '


## Helper Functions

def get_localpart_from_emailaddr(address):
    return address.rpartition('@')[0]

def get_domain_from_emailaddr(address):
    return address.rpartition('@')[2]

def chcon(filename, context):
    subprocess.check_call(('/usr/bin/chcon', context, filename))

def postmap(filename, maptype='cdb', selinux=False):
    """Run postmap on filename, (with the specified maptype)
    and give the generated map the same permissions as
    the file itself.
    Will always copy selinux contexts."""
    extension = {'hash': '.db', 'cdb': '.cdb'}

    if maptype not in extension:
        raise NotImplementedError

    try:
        subprocess.check_call(('postmap', ':'.join((maptype, filename))))
        logger.debug('Successfully mapped %s', ':'.join((maptype, filename)))
    except subprocess.CalledProcessError:
        logger.error('Could not update map %s:%s', maptype, filename)
        sys.exit(errno.EIO)

    base.permissions_from_reference(filename + extension[maptype],
                                         filename,
                                         selinux=selinux)

LOCKFILE = "/var/lock/genconfig"

def acquire_lock():
    """Acquires system-wide genconfig lock.
    Will return True if lock was acquired and False otherwise.
    If the lock was acquired already, will log this."""
    try:
        os.close(os.open(LOCKFILE, os.O_CREAT | os.O_EXCL | os.O_RDWR))
    except OSError, err:
        if err.errno != errno.EEXIST:
            raise
        return False
    return True

def release_lock():
    """Releases system-wide genconfig lock."""
    os.unlink(LOCKFILE)

def acquire_reported_lock():
    """Checks if a broken lock was already reported."""
    try:
        os.close(os.open(LOCKFILE + '.failed', os.O_CREAT | os.O_EXCL | os.O_RDWR))
    except OSError, err:
        if err.errno != errno.EEXIST:
            raise
        return False
    return True
    
def release_reported_lock():
    """Resets the reportedness of a broken lock."""
    os.unlink(LOCKFILE + '.failed')

def setup(loglevel=20):
    """Setup various things common to all machines"""
    logger.setLevel(loglevel)

    if not acquire_lock():
        if acquire_reported_lock() or once_hourly():
            # Lock is held by somebody else, and this is not reported yet.
            logger.critical("Could not acquire system-wide genconfig lock.")
            logger.critical("Will exit not having touched anything.")
            logger.critical("Subsequently, will only report hourly!")
        else:
            logger.debug("Could not acquire system-wide genconfig lock.")
            logger.debug("Will exit not having touched anything.")
        sys.exit(errno.EALREADY)
    else:
        if not acquire_reported_lock():
            # Lock could be acquired but it was reported it couldn't be acquired
            logger.warning("Lock was dropped, resuming normal function.")
            

def tear_down():
    release_lock()
    release_reported_lock()
    logging.shutdown()

if __name__ == '__main__':
    print(__doc__)
    print(__license__)
