"""Python utilities for pipe-like infix notation.
There are three distinct types of pipe-aware objects:
Producers do not consume any input, but generate output.
Filters consume input and generate output (most probably but not necessarily based on the input).
Sinks only consume input.
All input and output is passed on in chunks, which can consist of any python object. So
the data flowing through a pipe is a stream of chunks.
To get a full pipe, you have to connect a Producer to Sink, probably via some filters.
Pipe-aware objects are connected like in Posix shell with a '|', so valid combinations
are:
Producer | Sink
Producer | Filter [| AnotherFilter…] | Sink
Note that Producers and Filters are evaluated lazily. So the Sink "pulls" chunks out of
the connected Filters and Producers. So if the Sink is finished or can't even start (think
of a Sink writing to a file which doesn't have the necessary permissions), possibly
expensive Producing and Filtering is not done.
The pipe ends if the Sink stops pulling or the Producer (or Filter) is exhausted.

Instead of connecting a traditional Sink as the end of the pipe, you can end the pipe
with a write-to-file definition:
Producer [| Filters…] > 'filename'
which will pull chunks from the pipe and write str(chunk) one chunk per line to the file.
Similarly,
Producer [| Filters…] >> 'filename'
will append to the file.

Additionally to the Producers defined here, any python iterable can be used as a Producer,
for example a list:
[1, 2, 3] [| Filter…] | Sink

Have Fun!
"""

from . import base

from genconfig.filters import *
from genconfig.producers import *
from genconfig.sinks import *
from genconfig.base import *
from genconfig.utils import *

