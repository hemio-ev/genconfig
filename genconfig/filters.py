"""Filter classes for pipe-like infix syntax"""

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

import fcntl
import os
import logging
import shlex
import subprocess
import types
import copy

from . import base

logger = logging.getLogger('genconfig')

class tee(base.Filter):
    """Dumps whatever comes along and passes it on."""
    def __next__(self):
        chunk = self._chunk
        print(chunk)
        return chunk

class cat(base.Filter):
    """for list | cat > file constructs"""
    def __next__(self):
        return self._chunk

class where(base.Filter):
    def __init__(self, testing_function):
        base.Filter.__init__(self)
        self._testing_function = testing_function

    def __next__(self):
        chunk = self._chunk
        if self._testing_function(chunk):
            return chunk
        else:
            raise base.NeedData

class inject_from_producer(base.Filter):
    """Ignores input, produces instead."""
    def __init__(self, producer):
        base.Filter.__init__(self)
        self._producer = producer

    def __next__(self):
        return next(self._producer)

class multiply_chunk(base.RawFilter):
    """Passes chunks trough each supplied filter in turn, yielding all outputs
    after each other. You can use this to have one producer pass chunks to
    one sink through multiple, parallel filters such that the sink gets the output
    of each parallel filter in turn."""
    def __init__(self, *filters):
        base.RawFilter.__init__(self)
        self._filterobjects = filters

    def __enter__(self):
        self._filters = []
        self._exhausted_filters = []
        for filterobject in self._filterobjects:
            self._filters.append(filterobject.__enter__())
        self._reset_filters_with_enough_data()
        return self

    def __exit__(self, type_=None, value=None, traceback=None):
        for filt in self._filters + self._exhausted_filters:
            filt.__exit__(type_=None, value=None, traceback=None)
    
    def last(self):
        for filt in self._filters:
            filt.last()
        self._reset_filters_with_enough_data()
        
    def _reset_filters_with_enough_data(self):
        self._filters_with_enough_data = [x for x in self._filters] # copy not pointer

    def send(self, chunk):
        for filt in self._filters:
            filt.send(copy.deepcopy(chunk))
        self._reset_filters_with_enough_data()

    def __next__(self):
        if len(self._filters_with_enough_data) == 0: # no one has enough data at the moment
            if len(self._filters) == 0: # everyone is completely exhausted
                raise StopIteration
            raise base.NeedData

        while True:
            if len(self._filters_with_enough_data) == 0:
                break
            filt = self._filters_with_enough_data[0]
            try:
                return next(filt)
            except base.NeedData:
                # filter does not have enough data anymore
                self._filters_with_enough_data.remove(filt)
            except StopIteration:
                self._filters.remove(filt)
                self._exhausted_filters.append(filt)
                self._filters_with_enough_data.remove(filt)
        if self._filters:
            # we still have filters which can potentially become available if given data
            raise base.NeedData
        else:
            # all filters exhausted
            raise StopIteration
    
    def __str__(self):
        return "multiply_chunk(" + ', '.join([str(x) for x in self._filterobjects]) + ')'
            

class CheckLog(base.Filter):
    """Checks if the given condition evaluates to True.
    If it does, passes the chunk on, else logs it.
    Should be subclassed to provide the testing function and
    the log_string and the loglevel."""
    def __init__(self, key):
        base.Filter.__init__(self)
        self._key = key

    _loglevel = logging.WARN
    def __next__(self):
        chunk = self._chunk
        if self._testing_function(chunk[self._key]):
            return chunk
        else:
            logger.log(self._loglevel, self._log_string + str(chunk))
            raise base.NeedData

    def __str__(self):
        return 'CheckLog(%s, %s, %d)' % (str(self._testing_function), self._log_string, self._loglevel)
                
class take_while(base.Filter):
    def __init__(self, testing_function):
        base.Filter.__init__(self)
        self._testing_function = testing_function

    def __next__(self):
        chunk = self._chunk
        if not self._testing_function(chunk):
            raise StopIteration
        return chunk

class skip_while(base.Filter):
    def __init__(self, testing_function):
        base.Filter.__init__(self)
        self._testing_function = testing_function
        self._begun = False

    def __next__(self):
        chunk = self._chunk
        if self._begun or not self._testing_function(chunk):
            raise base.NeedData
        return chunk

class sort(base.FilterNeedsAll):
    def __init__(self, key=None, reverse=False):
        base.FilterNeedsAll.__init__(self)
        self._key = key
        self._reverse = reverse

    def _process(self, _input):
        return sorted(_input, key=self._key, reverse=self._reverse)

class reverse(base.FilterNeedsAll):
    def _process(self, _input):
        return reversed(_input)

class take(base.Filter):
    """Only pass on maxnum elements."""
    def __init__(self, maxnum):
        base.Filter.__init__(self)
        self._left = maxnum

    def __next__(self):
        chunk = self._chunk
        if self._left > 0:
            self._left -= 1
            return chunk
        raise StopIteration

class tail(base.RawFilter):
    """At most pass on the last n elements."""
    def __init__(self, n):
        base.RawFilter.__init__(self)
        self._queue = []
        self._n = n

    def send(self, chunk):
        self._queue.append(chunk)
        if len(self._queue) > self._n:
            self._queue.pop(0)

    def __next__(self):
        if not self._last:
            raise base.NeedData
        if not self._queue:
            raise StopIteration
        return self._queue.pop(0)

class skip(base.Filter):
    """Skips n elements, then passes everything through."""
    def __init__(self, n):
        base.Filter.__init__(self)
        self._to_go = n

    def __next__(self):
        chunk = self._chunk
        if self._to_go > 0:
            self._to_go -= 1
            raise base.NeedData
        return chunk

class sh_filter(base.RawFilter):
    def __init__(self, args, error_on_ret = False, **kwargs):
        base.RawFilter.__init__(self)
        if type(args) in (str,):
            args = shlex.split(args)
        if 'stdin' in kwargs or 'stdout' in kwargs:
            raise ValueError("Can't reroute stdin or stdout, they are piped!")
        self._args = args
        self._kwargs = kwargs
        self._error_on_ret = error_on_ret
        if error_on_ret:
            self._cmd = args[0]
        self._leftover = None

    def __enter__(self):
        self._subprocess = subprocess.Popen(self._args, 
                                            stdout=subprocess.PIPE, 
                                            stdin=subprocess.PIPE,
                                            **self._kwargs)
        base.unblock(self._subprocess.stdout)

        return self
    
    def last(self):
        self._leftover = self._subprocess.communicate()[0].splitlines()
        self._last = True

    def send(self, chunk):
        self._subprocess.stdin.write(''.join((chunk, '\n')))

    def __next__(self):
        # Read anything the process yields
        try:
            line_ = self._subprocess.stdout.readline()
        except (IOError, ValueError):
            if self._last:
                if self._leftover:
                    return self._leftover.pop(0)
                else:
                    if self._error_on_ret and not self._subprocess.retcode == 0:
                        raise subprocess.CalledProcessError(self._subprocess.retcode, self._cmd)
                raise StopIteration
            else:
                raise base.NeedData
        if line_ == '':
            raise StopIteration
        return line_.splitlines()[0]

class unique(base.Filter):
    def __init__(self):
        base.Filter.__init__(self)
        self._seen = []

    def __next__(self):
        chunk = self._chunk
        if chunk not in self._seen:
            self._seen.append(chunk)
            return chunk
        raise base.NeedData

    def __str__(self):
        return 'unique()'

class running_sum(base.Filter):
    def __init__(self):
        base.Filter.__init__(self)
        self._value = 0

    def __next__(self):
        self._value += self._chunk
        return self._value

    def __str__(self):
        return 'running_sum()'

class running_average(base.Filter):
    """Averages piped in arguments. Returns the total average up to
    now at each point."""
    def __init__(self):
        base.Filter.__init__(self)
        self._average = 0.0
        self._num = 0

    def __next__(self):
        self._num += 1
        self._average += (self._chunk - self._average) / self._num
        return self._average

class apply(base.Filter):
    """Applies the given function to every element piped to it."""
    def __init__(self, function):
        base.Filter.__init__(self)
        self._function = function
    
    def __next__(self):
        return self._function(self._chunk)

    def __str__(self):
        return 'apply(%s)' % str(self._function)

class to_formatted_string(base.Filter):
    """Apply "format_string % x" to every input x."""
    def __init__(self, format_string):
        base.Filter.__init__(self)
        self._format = format_string

    def __next__(self):
        return self._format % self._chunk

    def __str__(self):
        return 'to_formatted_string(%s)' % self._format

class to_passwd_line(base.Filter):
    """Convert a dictionary containing the keys
    'name', 'password', 'uid', 'gid', 'gecos', 'home'
    and 'shell' into a line suitable for writing to a
    passwd(5) file."""

    template = '%(name)s:%(password)s:%(uid)d:%(gid)d:%(gecos)s:%(home)s:%(shell)s'

    def __next__(self):
        return self.template % self._chunk

    def __str__(self):
        return 'passwd()'

class to_passwd_line_with_quota(to_passwd_line):
    """Like passwd, but with an extra quota field, which is filled only if
    quota is not None"""
    quota_template = to_passwd_line.template + ':userdb_quota_rule=*:bytes=%(quota)dM'

    def __next__(self):
        chunk = self._chunk
        if chunk['quota'] is None:
            return self.template % chunk
        else:
            return self.quota_template % chunk

    def __str__(self):
        return 'passwd_quota()'

class to_shadow_line(base.Filter):
    """Convert a dictionary containing the keys 'name', 'password',
    'lastchange', 'minage', 'maxage', 'warning_period', 'inact_period',
    'expire_date', 'reserved' into at line suitable for writing to
    a shadow(5) file.
    Only name and password are required, the rest will be left empty
    if not given.
    -1 will be interpreted as None."""

    template = '%(name)s:%(password)s:%(lastchange)s:%(minage)s:%(maxage)s:%(warning_period)s:%(inact_period)s:%(expire_date)s:%(reserved)s'

    def __next__(self):
        chunk = self._chunk
        for i in ('lastchange', 'minage', 'maxage', 'warning_period', 'inact_period', 'expire_date', 'reserved'):
            chunk.setdefault(i, '')
            if chunk[i] == -1:
                chunk[i] = ''
        return self.template % chunk

    def __str__(self):
        return 'to_shadow_line()'

class to_group_line(base.Filter):
    """Convert a dictionary containing the keys
    'group_name', 'group_password', , 'gid' and
    and 'member_list' into a line suitable for writing to a
    group(5) file."""

    template = '%(group_name)s:%(group_password)s:%(gid)d:%(_member_list_str)s'

    def __next__(self):
        chunk = self._chunk
        chunk['_member_list_str'] = ','.join(chunk['member_list'])
        return self.template % chunk

    def __str__(self):
        return 'to_group_line()'

class to_gshadow_line(base.Filter):
    """Convert a dictionary containing the keys
    'group_name', 'group_password', 'administrator_list' and
    and 'member_list' into a line suitable for writing to a
    group(5) file."""

    template = '%(group_name)s:%(group_password)s:%(_administrator_list_str)s:%(_member_list_str)s'

    def __next__(self):
        chunk = self._chunk
        chunk['_administrator_list_str'] = ','.join(chunk['administrator_list'])
        chunk['_member_list_str'] = ','.join(chunk['member_list'])
        return self.template % chunk

    def __str__(self):
        return 'to_gshadow_line()'

class to_apache2_vhost(base.Filter):

    template_vhost = """
<VirtualHost *:{port}>
    Use GenconfigVhostDefaults "{user}" "{user_cgi}" "{domain}" "{port}" "{aliases}"
</VirtualHost>
"""
    template_vhost_ssl = """
MDomain "{domain}"
<VirtualHost *:{port}>
    Use GenconfigVhostDefaults "{user}" "{user_cgi}" "{domain}" "{port}" "{aliases}"
    SSLEngine On
</VirtualHost>
"""

    def __next__(self):
        chunk = self._chunk

        res = ""

        if chunk['https']:
            res += self.template_vhost_ssl.format(**chunk)
            if chunk['port'] == 443:
                nchunk = chunk.copy()
                nchunk.update(port=80)
                res += self.template_vhost.format(**nchunk)
        else:
            res += self.template_vhost.format(**chunk)

        return res

    def __str__(self):
        return 'to_apache2_vhost()'

class FromValue(base.Filter):
    """MixIn class for writing from value.
    Mix it with one of the setting method classes."""
    def __init__(self, newkey, value):
        base.Filter.__init__(self)
        self._newkey = newkey
        self._value = value

    def __next__(self):
        chunk = self._chunk
        if type(self._value) in (str,):
            value = self._value % chunk
        else:
            value = self._value
        return self._set(chunk, self._newkey, value)

class FromKey(base.Filter):
    """MixIn class for writing from existing key."""
    def __init__(self, newkey, oldkey):
        base.Filter.__init__(self)
        self._newkey = newkey
        self._oldkey = oldkey

    def __next__(self):
        chunk = self._chunk
        return self._set(chunk, self._newkey, chunk[self._oldkey])

class FromFunction(base.Filter):
    """MixIn class for writing from a function applied to the chunk."""
    def __init__(self, newkey, function):
        base.Filter.__init__(self)
        self._newkey = newkey
        self._function = function

    def __next__(self):
        chunk = self._chunk
        return self._set(chunk, self._newkey, self._function(chunk))

class Override(object):
    def _set(self, chunk, newkey, newval):
        chunk[newkey] = newval
        return chunk

class Add(object):
    def _set(self, chunk, newkey, newval):
        if newkey in chunk:
            raise KeyError('Key exists already: %s' % newkey)
        chunk[newkey] = newval
        return chunk

class Default(object):
    def _set(self, chunk, newkey, newval):
        chunk.setdefault(newkey, newval)
        return chunk

class add_from_key(Add, FromKey):
    """Add a new key from an existing key."""

class add_from_value(Add, FromValue):
    """Add a new key from a constant value (which will be expanded via % chunk if it is a string)"""

class add_from_function(Add, FromFunction):
    """Add a new key from a function applied to chunk."""

class override_from_key(Override, FromKey):
    """Add a new key or override existing key from another existing key."""

class override_from_value(Override, FromValue):
    """Add a new key or override existing key from a constant value
    (which will be expanded via % chunk if it is a string)"""

class override_from_function(Override, FromFunction):
    """Add a new key or override existing key from a function applied to chunk."""

class default_from_key(Default, FromKey):
    """Set a key if not set from an existing key."""

class default_from_value(Default, FromValue):
    """Set a key if not set from a constant value
    (which will be expanded via % chunk if it is a string)"""

class default_from_function(Default, FromFunction):
    """Set a key if not set from a function applied to chunk."""

class inject(base.Filter):
    """Injects given object into the stream."""
    def __init__(self, obj):
        base.Filter.__init__(self)
        self._obj = obj
        self._injected = False

    def __next__(self):
        if not self._injected:
            chunk = self._obj
            self._injected = True
        else:
            chunk = self._chunk
        return chunk

def format_if_string(obj, dict_):
    if type(obj) in (str,):
        return obj % dict_
    else:
        return obj


class replace_from_key(base.Filter):
    def __init__(self, newkey, oldvalue, oldkey):
        base.Filter.__init__(self)
        self._key = newkey
        self._oldvalue = oldvalue
        self._oldkey = oldkey

    def __next__(self):
        chunk = self._chunk
        try:
            if chunk[self._key] == format_if_string(self._oldvalue, chunk):
                chunk[self._key] = chunk[self._oldkey]
        except KeyError:
            pass
        return chunk

class replace_from_value(base.Filter):
    def __init__(self, newkey, oldvalue, newvalue):
        base.Filter.__init__(self)
        self._key = newkey
        self._oldvalue = oldvalue
        self._newvalue = newvalue

    def __next__(self):
        chunk = self._chunk
        try:
            if chunk[self._key] == format_if_string(self._oldvalue, chunk):
                chunk[self._key] = format_if_string(self._newvalue, chunk)
        except KeyError:
            pass
        return chunk

class replace_from_function(base.Filter):
    def __init__(self, newkey, oldvalue, function):
        base.Filter.__init__(self)
        self._key = newkey
        self._oldvalue = oldvalue
        self._function = function

    def __next__(self):
        chunk = self._chunk
        try:
            if chunk[self._key] == format_if_string(self._oldvalue):
                chunk[self._key] = self._function(chunk)
        except KeyError:
            pass
        return chunk

class to_dict(base.Filter):
    def __init__(self, keys=None):
        base.Filter.__init__(self)
        self._keys = keys

    def __next__(self):
        chunk = self._chunk
        if self._keys is None:
            return dict(chunk)
        else:
            d = {}
            for i, key in enumerate(self._keys):
                d[key] = chunk[i]

    def __str__(self):
        if self._keys is None:
            return 'to_dict()'
        else:
            return 'to_dict(%s)' % (str(self._keys))

class to_string(base.Filter):
    def __next__(self):
        return str(self._chunk)

    def __str__(self):
        return 'to_str()'

class traverse(base.Filter):
    def __next__(self):
        chunk = self._chunk
        try:
            if type(chunk) in (str,):
                return chunk
            else:
                with chunk | traverse() | to_string() as source:
                    for i in source:
                        return i
        except TypeError:
            return chunk

    def __str__(self):
        return 'traverse()'

class log(base.Filter):
    """Logs the input and passes it on."""
    def __init__(self, msg='', loglevel=10):
        base.Filter.__init__(self)
        self._loglevel = loglevel
        self._msg = msg

    def __next__(self):
        chunk = self._chunk
        logger.log(self._loglevel, ' :'.join((self._msg, str(chunk))))
        return chunk

    def __str__(self):
        if self._loglevel == 10:
            return 'log(%s)' % self._msg
        else:
            return 'log(%s, %s)' % (self._msg, str(self._loglevel))

class debug(log):
    def __init__(self, msg=''):
        log.__init__(self, msg, loglevel=logging.DEBUG)
    
    def __str__(self):
        return 'debug(%s)' % self._msg

class info(log):
    def __init__(self, msg=''):
        log.__init__(self, msg, loglevel=logging.INFO)

    def __str__(self):
        return 'info(%s)' % self._msg

class warn(log):
    def __init__(self, msg=''):
        log.__init__(self, msg, loglevel=logging.WARN)

    def __str__(self):
        return 'warn(%s)' % self._msg

class error(log):
    def __init__(self, msg=''):
        log.__init__(self, msg, loglevel=logging.ERROR)

    def __str__(self):
        return 'error(%s)' % self._msg

class critical(log):
    def __init__(self, msg=''):
        log.__init__(self, msg, loglevel=logging.CRITICAL)

    def __str__(self):
        return 'critical(%s)' % self._msg
