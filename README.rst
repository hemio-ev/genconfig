genconfig
=========

Generate server configurations from a database or similar source.

In this file are guidelines how to work with the source, that is, this README is intended for use
when developing the scripts for the generation of the script, not for deployment.

General guidelines:
There are roughly two parts - the configuration files of the individual machines like *examples/\*.py*,
which are written in a domain-specific language derived from python (it is actually python,
but doesn't look like python and violates quite a lot of conventions) and the rest, which is 
actually written in python.

Short explanation of the domain-specific part:

* It is python, you can do anything you can do in python.
* Make a new config by copying kresse.py and removing all the kresse-stuff. Then, have fun
  adding functionality.
* The actually working lines follow a data-flow model, where a Sink consumes values which
  come (possibly through Filters) from Producers.
* The maybe most important producer is the ``from_db_procedure(conn, sql_procedure, arguments)``
  producer, which does what you would think: it gives you a dictionary of the stuff the
  database gives back when calling the sql_procedure with the arguments.
* There's hopefully a Filter for anything you would want to do.
* probably the most useful Sink is the file sink. It works like in the shell:

  .. code-block:: py

   > 'filename'

  writes to the filename whatever comes along. It does so atomically + securely, and if ``'filename'``
  already exists, gets permissions etc. from there. To also copy selinux contexts, use ``>= 'filename'``

Please commit stuff to git you are working on, if it is not usable at the moment, use a branch.
