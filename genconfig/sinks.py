"""Sink classes for pipe-like infix syntax"""

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

from . import base

class dump(base.Sink):
    """Prints out all chunks."""
    def send(self, chunk):
        print(chunk)

class concat(base.SinkNeedsAll):
    """Concatenate everything that comes along."""
    def __init__(self, separator=', '):
        base.SinkNeedsAll.__init__(self)
        self._separator = separator

    def result(self):
        return self._separator.join((str(x) for x in self._input))

class all_(base.Sink):
    """Evaluates to True if all piped in arguments evaluate to
    True."""
    def __init__(self):
        base.Sink.__init__(self)
        self._truth = True

    def send(self, chunk):
        if self._truth and not chunk:
            self._truth = False
    
    def result(self):
        return self._truth

class any_(base.Sink):
    """Evaluates to True if any of the piped in arguments evaluate to
    True."""
    def __init__(self):
        base.Sink.__init__(self)
        self._truth = False

    def send(self, chunk):
        if not self._truth and chunk:
            self._truth = True

    def result(self):
        return self._truth

class average(base.Sink):
    """Averages piped in arguments. Returns total average."""
    def __init__(self):
        base.Sink.__init__(self)
        self._num = 0
        self._average = 0.0

    def send(self, chunk):
        self._num += 1
        self._average += (chunk - self._average) / self._num

    def result(self):
        return self._average

class count(base.Sink):
    """Return total count of piped in values."""
    def __init__(self):
        base.Sink.__init__(self)
        self._num = 0

    def send(self, chunk):
        self._num += 1

    def result(self):
        return self._num

class HighestValue(object):
    """Higher than anything."""
    def __cmp__(self, other):
        return 1

class LowestValue(object):
    def __cmp__(self, other):
        return -1

class max_(base.Sink):
    """Return highest value."""
    def __init__(self):
        base.Sink.__init__(self)
        self._max = LowestValue()

    def send(self, chunk):
        self._max = max((self._max, chunk))

    def result(self):
        return self._max

class min_(base.Sink):
    """Return lowest value."""
    def __init__(self):
        base.Sink.__init__(self)
        self._min = HighestValue()

    def send(self, chunk):
        self._min = min((self._min, chunk))

    def result(self):
        return self._min

class do(base.Sink):
    """Just pulls from the pipe, does nothing with the pulled values.
    Evaluates to True."""

    def send(self, chunk):
        pass

class append_to_list(base.SinkNeedsAll):
    """Return all piped in elements in a list, appends them to a given list"""
    def __init__(self, list_ = None):
        base.SinkNeedsAll.__init__(self)
        self._list = list_

    def result(self):
        if self._list is None:
            return self._input
        else:
            for chunk in self._input:
                self._list.append(chunk)

