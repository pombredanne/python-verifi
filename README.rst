======
verifi
======

Verify SSL/TLS certificate chains.

::
	
	>>> import verifi
	>>> errors = verifi.verify('www.konklone.com')

*errors* will be a list of *verifi.VerificationError* objects representing issues found in the certificate chain. If errors is empty, everything is good!

The *verifi.VerificationError* object has two important attributes:

* message - the error message as a string
* cert - a *verifi.Certificate* instance of the cert that contained the error
  

Installation
============

Available on `PyPI as verifi <https://pypi.python.org/pypi/verifi>`_.

  pip install verifi


Command Line Usage
==================

verifi provides a command line utility that will list all certificate issues for a given hostname::

	$ verifi www.konklone.com
	Verifying certs at www.konklone.com
	OK!

	$ verifi konklone.com
	Verifying certs at konklone.com
	Found the following issues:
	- Hostname does not match [www.konklone.com]
	FAILED!

	$ verifi -h
	usage: verifi.py [-h] [-p PORT] HOSTNAME

	Verify TLS certificate chain.

	positional arguments:
	  HOSTNAME              site to verify

	optional arguments:
	  -h, --help            show this help message and exit
	  -p PORT, --port PORT  host port (default: 443)
