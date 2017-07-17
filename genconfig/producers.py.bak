#!/usr/bin/python
# -*- coding: utf-8
"""Producer classes for pipe-like infix syntax"""

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

import subprocess
import shlex

from . import base

class sh(base.Producer):
    """Produce from a shell command"""
    def __init__(self, args, error_on_ret = False, **kwargs):
        base.Producer.__init__(self)
        if type(args) in types.StringTypes:
            args = shlex.split(args)
        if 'stdout' in kwargs:
            raise ValueError("Can't reroute stdout, it is piped!")
        self._args = args
        self._kwargs = kwargs
        self._error_on_ret = error_on_ret
        if error_on_ret:
            self._cmd = args[0]
        self._leftover = None

    def __enter__(self):
        self._subprocess = subprocess.Popen(self._args, 
                                            stdout=subprocess.PIPE, 
                                            **self._kwargs)
        return self
    
    def next(self):
        # Read anything the process yields
        line_ = self._subprocess.stdout.readline()
        if line_ == '':
            raise StopIteration

        return line_.splitlines()[0]

    def __exit__(self, type_=None, value=None, traceback=None):
        self._subprocess.wait()
        if self._error_on_ret and not self._subprocess.returncode == 0:
            raise subprocess.CalledProcessError(self._subprocess.returncode, self._cmd)


class echo(base.Producer):
    """Produce a single string"""
    def __init__(self, out):
        base.Producer.__init__(self)
        self.out = out

    def next(self):
        if self.out is not None:
            ret = self.out
            self.out = None
            return ret
        raise StopIteration

        
