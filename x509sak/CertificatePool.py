#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2019 Johannes Bauer
#
#	This file is part of x509sak.
#
#	x509sak is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	x509sak is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with x509sak; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import os
import collections
import datetime
import logging
from .X509Certificate import X509Certificate

_log = logging.getLogger("x509sak.CertificatePool")

class CertificatePool():
	_CertificateChain = collections.namedtuple("CertificateChain", [ "root", "chain", "leaf", "full_chain" ])
	def __init__(self):
		self._pool = collections.defaultdict(set)

	@property
	def certificate_count(self):
		return sum(len(certs) for certs in self._pool.values())

	def find_chain(self, certificate, max_depth = 100):
		now = datetime.datetime.utcnow()
		leaf = certificate
		chain = [ ]
		for _ in range(max_depth):
			issuers = list(self.find_issuers(certificate))
			if len(issuers) == 0:
				issuer = None
				break

			# If there's multiple issuers, prefer those which are currently
			# valid and, as a second criterion, those which are valid for the
			# longest time period.
			issuers.sort(key = lambda crt: (not crt.is_time_valid(now), -crt.seconds_until_expires(now)))
			issuer = issuers[0]
			if issuer == certificate:
				break
			chain.append(issuer)
			certificate = issuer

		full_chain = [ leaf ] + chain
		if issuer == certificate:
			# Got a root cert
			root = certificate
			chain = tuple(chain[:-1])
		else:
			# Partial chain match
			root = None
			chain = tuple(chain)
		return self._CertificateChain(root = root, chain = chain, leaf = leaf, full_chain = tuple(full_chain))

	def find_issuers(self, subject_cert):
		if subject_cert.issuer == subject_cert.subject:
			if subject_cert.signed_by(subject_cert):
				yield subject_cert

		if subject_cert.issuer in self._pool:
			for possible_issuer_cert in self._pool[subject_cert.issuer]:
				if possible_issuer_cert != subject_cert:
					if subject_cert.signed_by(possible_issuer_cert):
						yield possible_issuer_cert

	def add_certificate(self, cert):
		self._pool[cert.subject].add(cert)

	def add_certificates(self, certs):
		for cert in certs:
			self.add_certificate(cert)

	def load_pemfile(self, filename):
		certs = X509Certificate.read_pemfile(filename, ignore_errors = True)
		for cert in certs:
			self.add_certificate(cert)

	def load_pemdirectory(self, dirname, extensions = None):
		if extensions is None:
			extensions = set([ ".crt", ".pem" ])
		if not dirname.endswith("/"):
			dirname += "/"
		for filename in os.listdir(dirname):
			for extension in extensions:
				if filename.endswith(extension):
					break
			else:
				continue
			fullfilename = dirname + filename
			self.load_pemfile(fullfilename)

	def load_source(self, pathname, extensions = None):
		if os.path.isfile(pathname):
			_log.debug("Loading CA certificate from %s", pathname)
			self.load_pemfile(pathname)
		elif os.path.isdir(pathname):
			_log.debug("Loading CA certificates from directory %s", pathname)
			self.load_pemdirectory(pathname, extensions = extensions)
		else:
			raise Exception("Unable to load trust store source %s: No such file or directory" % (pathname))

	def load_sources(self, sources, extensions = None):
		for source in sources:
			self.load_source(source, extensions = extensions)

	def dump(self):
		for (subject, certs) in self._pool.items():
			print("Subject %s:" % (subject))
			for cert in certs:
				print("   %s" % (cert))

	def __iter__(self):
		for certs in list(self._pool.values()):
			for cert in list(certs):
				yield cert
