"""Base classes for pipe-like infix syntax"""

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

import os
import shutil
import subprocess
import types
import copy
import fcntl

class NeedData(Exception):
    def __str__(self):
        return "Filter needs more data to produce output."

class Pipe(object):
    """Base class for Pipe objects.
    You shouldn't directly subclass this, but one of the higher-level classes."""
    def __init__(self):
        pass

    def __or__(self, other):
        """Explicitly call the other's __ror__ as it is 
        not called if self and other are instances of the same class."""
        return other.__ror__(self)

    def __iter__(self):
        return self

    def __call__(self):
        return self


class EasyWriteMixIn(object):
    """Allows to write easily to files (syntactic sugar):
    Producer > 'filename'   writes to file
    Filter   > 'filename'   gives a Sink writing filtered values to file
    Producer >> 'filename'  appends to filename
    Producer >= 'filename'  selinux-aware version of >
    """

    def __gt__(self, target):
        """Write to target, which can either be a file-like object,
        or a string in which case it will be treated as a path to
        a file to be overwritten."""
        return self | write_securely_to_file(target)

    def __rshift__(self, target):
        """Write to target, which can either be a file-like object,
        or a string in which case it will be treated as a path to
        a file to which output will be appended."""
        return self | append_to_file(target)

    def __ge__(self, target):
        """selinux-aware version of __gt__"""
        return self | write_securely_to_file(target, selinux=True)


class RawFilter(Pipe, EasyWriteMixIn):
    """Base class for Filter objects.
    Filter objects follow a defined protocol:
    First, Filter.__enter__() is called. It returns the Filter
    Then, Filter.next() is called when a new chunk is needed.
    The Filter then may:
    * return the next chunk - you can call Filter.next() again if you need 
      another chunk
    * raise the NeedData exception - you then have to provide input to the
      Filter (see section on input). You can then try again to obtain a chunk
      via Filter.next()
    * raise a StopIteration exception - there will be no further output
      from the Filter. It is pointless to provide more input, the filter is
      ultimately exhausted.
    Note that the protocol is absolutely strict. You have to follow the detailed
    protocol in all respects, otherwise the behaviour is undefined. So, for example,
    you are not allowed to provide input to the Filter unless it raised a NeedData
    exception when Filter.next() was called.
    To provide input you can either:
    * call Filter.send(chunk), sending the filter one chunk of data. You may only
      send one chunk of input at a time, afterwards you have to try to obtain
      output from the Filter. Filters don't buffer.
    * call Filter.last() to notify the Filter that input is exhausted and there will
      be no more input. Many Filters that need to know the whole dataset (like e.g.
      max_) will only yield output after being notified that input is exhausted.
    After providing input, you can try again to get a chunk of output.
    If either StopIteration was raised when you tried to obtain output or you are
    no longer interested in output from the Filter, you have to call Filter.__exit__()
    for any cleanup to happen.

    This Base class RawFilter should only be subclassed by Filters which need full control over
    the protocol. For common cases see the Filter class (functions operating on one
    chunk of data at a time, yielding one chunk of output for every input) and the
    FilterNeedsAll class (functions that require the full set of inputs for any output).

    If subclassing RawFilter, please overwrite send, next and (if needed) __enter__ and/or
    __exit__ with your implementations. You can overwrite last or rely on the behaviour
    that RawFilter._last is True when last was called, False otherwise.

    """
    def __init__(self):
        Pipe.__init__(self)
        self._last = False

    def __enter__(self):
        return self

    def __exit__(self, type_=None, value=None, traceback=None):
        pass

    def last(self):
        self._last = True

    def send(self, chunk):
        pass

    def __next__(self):
        raise StopIteration

    def __ror__(self, other):
        if isinstance(other, RawFilter):
            return CombinedFilter(other, self)
        elif isinstance(other, Producer):
            return FilteredProducer(other, self)
        else:
            return FilteredProducer(IteratorProducer(other), self)


class Filter(RawFilter):
    """Higher-Level class for subclassing to make Filter objects.
    This class aids you in implementing the Filter protocol (see
    the RawFilter docstring). It is suitable for Filters which
    return one chunk of data for every chunk of input.
    You simply overwrite the next() function. You can rely on
    Filter._input containing a chunk of data. Note that
    you can only access Filter._input once per next()-cycle,
    if you need it more than once, you have to store it in a local
    variable. Accessing Filter._input raises NeedData or StopIteration
    exceptions as needed, you don't have to worry about them.
    If you want to, you can provide your own __enter__() and/or
    __exit__() functions, but you must not overwrite last().
    """
    def __init__(self):
        RawFilter.__init__(self)
        self._real_input = None
        self._input_avail = False

    def _get_chunk(self):
        if self._input_avail:
            self._input_avail = False
            return self._real_input
        else:
            if self._last:
                raise StopIteration
            else:
                raise NeedData

    def _set_chunk(self, value):
        self._input_avail = True
        self._real_input = value

    _chunk = property(_get_chunk, _set_chunk)

    def __next__(self):
        return self._chunk
    
    def send(self, chunk):
        self._chunk = chunk

class CombinedFilter(RawFilter):
    def __init__(self, source, target):
        RawFilter.__init__(self)
        self._source = source
        self._target = target
        self._source_exhausted = False

    def __str__(self):
        return ' | '.join((str(_self.source), str(self._target)))

    def send(self, chunk):
        self._source.send(chunk)

    def last(self):
        self._source.last()

    def __next__(self):
        # Try if we can get a value from the target
        # without providing more info
        # A StopIteration from the target will be propagated
        try:
            return next(self._target)
        except NeedData:
            pass
        # Target needs data - will pull chunks from the source
        # and send them to the target until the target returns
        # something or the source is exhausted.
        # A StopIteration from the source means we need to notify
        # the target about last(), a StopIteration from the target
        # will simply be propagated to the caller
        while True:
            if not self._source_exhausted:
                try:
                    self._target.send(next(self._source))
                    # The maybe raised NeedData will just be propagated
                    # to the caller, which is fine -- we are in a need
                    # of data then.
                except StopIteration:
                    self._target.last()
                    self._source_exhausted = True
            try:
                return next(self._target)
            except NeedData:
                pass

    def __enter__(self):
        self._source = self._source.__enter__()
        self._target = self._target.__enter__()
        return self

    def __exit__(self, type_=None, value=None, traceback=None):
        self._source.__exit__()
        self._target.__exit__()

class combine(object):
    """Combine two Filters."""
    def __init__(self, source, target):
        self._source = source
        self._target = target

    def __call__(self):
        return CombinedFilter(self._source, self._target)


class FilterNeedsAll(RawFilter):
    """Base class for Filters that need the whole dataset to operate.
    If you subclass this class, you need to provide a FilterNeedsAll._process(input_)
    function, which will be given a list of all input.
    It must return an iterable of output.
    You can provide your own __enter__() and/or __exit__() functions, but you
    must not overwrite last(), send(chunk) or next().
    """
    def __init__(self):
        RawFilter.__init__(self)
        self._input = []
        self._output = []
        self._processed = False

    def __next__(self):
        if not self._last:
            raise NeedData
        if not self._processed:
            self._output = iter(self._process(self._input))
            self._processed = True
        return next(self._output)

    def send(self, chunk):
        self._input.append(chunk)


class Producer(Pipe, EasyWriteMixIn):
    """Producer base class.
    Producers generate output without being given input. They follow
    an easy protocol:
    First, you have to call Producer.__enter__(), then you can get output
    from the Producer by calling Producer.next() until you either
    are not interested in output anymore or a StopIteration is raised
    by the Producer, then you have to call Producer.__exit__(). As Producers
    closely follow the iterator protocol, they can be used like so:
    with Producer() as prod:
        for i in prod:
            # whatever

    When subclassing, you should provide a useful next() function and
    can overwrite the __enter__() and/or __exit__() functions.
    """
    def __init__(self):
        Pipe.__init__(self)

    def __enter__(self):
        return self

    def __exit__(self, type_=None, value=None, traceback=None):
        pass

    def __next__(self):
        raise StopIteration


class IteratorProducer(Producer):
    """Make a Producer from an iterator.
    Given an iterator, this implements the Producer protocol, which is
    obviously easy.
    """
    def __init__(self, iterator):
        Producer.__init__(self)
        self._iterator = iter(iterator)

    def __next__(self):
        return next(self._iterator)

    def __repr__(self):
        return "IteratorProducer(%s)" % repr(self._iterator)

    def __str__(self):
        return "IteratorProducer(%s)" % str(self._iterator)

class FilteredProducer(Producer):
    """Combination of a Producer and a Filter is a Producer again.
    So you can stack Filters on Producers.
    Given a Producer and a Filter this is a Producer.
    """
    def __init__(self, producer, filter_):
        Producer.__init__(self)
        self._producer = producer
        self._filter = filter_
        self._producer_exhausted = False

    def __enter__(self):
        self._producer = self._producer.__enter__()
        self._filter = self._filter.__enter__()
        return self

    def __exit__(self, type_=None, value=None, traceback=None):
        self._producer.__exit__()
        self._filter.__exit__()

    def __next__(self):
        # StopIteration would be propagated to the caller
        try:
            return next(self._filter)
        except NeedData:
            # no more data for the filter
            if self._producer_exhausted:
                raise StopIteration
            while True:
                # StopIteration of the producer means we have to call last on the filter
                try:
                    self._filter.send(next(self._producer))
                except StopIteration:
                    self._producer_exhausted = True
                    self._filter.last()
                try:
                    return next(self._filter)
                except NeedData:
                    # no more data for the filter
                    if self._producer_exhausted:
                        raise StopIteration

    def __repr__(self):
        return "FilteredProducer(%s, %s)" % (repr(self._producer), repr(self._filter))

    def __str__(self):
        return " | ".join((str(self._producer), str(self._filter)))


class Sink(Pipe):
    """Pulling data if connected to a Source, otherwise
    waits to be connected.
    When connected to a source which follows the Producer protocol, it will
    evaluate to some result.

    When subclassing, you should overwrite the send function and 
    the result function.
    """
    def __init__(self):
        Pipe.__init__(self)
        EasyWriteMixIn.__init__(self)

    def _pull(self, source):
        source = source.__enter__()
        for chunk in source:
            try:
                self.send(chunk)
            except StopIteration:
                break
        source.__exit__()
        return self.result()

    def result(self):
        return None

    def __ror__(self, source):
        if isinstance(source, RawFilter):
            return FilteredSink(source, self)
        elif isinstance(source, Producer):
            return self._pull(source)
        else:
            return self._pull(IteratorProducer(source))

    def __and__(self, other):
        return MultiSink([self, other])

    def send(self, chunk):
        raise StopIteration

class SinkNeedsAll(Sink):
    """Highlevel Sink base class for sinks that need the complete data set.
    When subclassing, just provide a result() function, which can rely on
    SinkNeedsAll._input containing the list of piped in values.
    """
    def __init__(self):
        Sink.__init__(self)
        self._input = []

    def send(self, chunk):
        self._input.append(chunk)

class FilteredSink(Sink):
    def __init__(self, filter_, sink):
        Sink.__init__(self)
        self._filter = filter_.__enter__()
        self._sink = sink
        self._premature_close = False
        while True:
            try:
                self._sink.send(next(self._filter))
            except NeedData:
                break
            except StopIteration:
                self._premature_close = True
                break

    def result(self):
        self._filter.__exit__()
        return self._sink.result()
        
    def send(self, chunk):
        if self._premature_close:
            raise StopIteration
        self._filter.send(chunk)
        while True:
            try:
                self._sink.send(next(self._filter))
            except NeedData:
                break

    def __str__(self):
        return '( %s | %s )' % (str(self._filter), repr(self._sink))


class MultiSink(Sink):
    def __init__(self, targets):
        Sink.__init__(self)
        self._targets = targets
        self._running_targets = targets

    def __str__(self):
        return "(%s)" % ' & '.join(self._targets)

    def __and__(self, target):
        self._targets.append(target)
        return self

    def result(self):
        result = []
        for target in self._targets:
            result.append(target.result())
        return result

    def send(self, chunk):
        if not self._running_targets:
            raise StopIteration
        remaining_targets = []
        for target in self._running_targets:
            try:
                target.send(copy.deepcopy(chunk))
                remaining_targets.append(target)
            except StopIteration:
                pass
        self._running_targets = remaining_targets

# The only individual Sinks actually defined in base, as they are needed in the base classes
def unblock(file_):
    """Unblock the given file_
    Adds O_NONBLOCK to the file's flags."""
    fl = fcntl.fcntl(file_, fcntl.F_GETFL)
    return fcntl.fcntl(file_, fcntl.F_SETFL, fl | os.O_NONBLOCK)

def permissions_from_reference(filename, reffilename, selinux=False):
    """Copies permissions (and optionally selinux contexts) from
    reffile to file. Panics if it fails."""
    if selinux:
        subprocess.check_call(('/usr/bin/chcon',
                               '--reference', reffilename,
                               filename))
    
    subprocess.check_call(('/bin/chown',
                           '--reference', reffilename,
                           filename))
    shutil.copymode(reffilename, filename)


class write_securely_to_file_template(Sink):
    """A sink that writes securely to files given a template."""
    def __init__(self, key, target_template, selinux=False):
        Sink.__init__(self)
        self._selinux = selinux
        self.target_template = target_template
        self.key = key
            
    def send(self, chunk):
        # need to do the whole dance - open file, write it, close it.
        target = self.target_template % chunk
        fd = open(target + '.new', 'w')
        if os.path.isfile(target):
            permissions_from_reference(target + '.new', target, self._selinux)
        fd.write(''.join((chunk[self.key], '\n')))
        fd.flush()
        os.fsync(fd.fileno())
        shutil.move(target + '.new', target)


class write_securely_to_file(Sink):
    """A sink that writes securely to a file given as a filename.
    Alternatively, if you give it a file-like object, it will naively write to it.
    """
    def __init__(self, target, selinux=False):
        Sink.__init__(self)
        self._selinux = selinux
        if type(target) in (str,):
            self._managed = True
            self._fd = open(target + '.new', 'w')
            self._target = target
            if os.path.isfile(target):
                permissions_from_reference(target + '.new', target, selinux)
        else:
            self._managed = False
            self._fd = target

    def result(self):
        if self._managed:
            self._fd.flush()
            os.fsync(self._fd.fileno())
            self._fd.close()
            shutil.move(self._target + '.new', self._target)
        return True
            
    def send(self, chunk):
        self._fd.write(''.join((chunk, '\n')))

class append_to_file(write_securely_to_file):
    def __init__(self, target):
        write_securely_to_file.__init__(self, target)
        if type(target) in (str,):
            self._managed = True
            self._fd = open(target + '.new', 'a')
        else:
            self._managed = False
            self._fd = target
        

    def result(self):
        if self._managed:
            self._fd.flush()
            os.fsync(self._fd.fileno())
            self._fd.close()
        return True
