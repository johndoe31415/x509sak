#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2018 Johannes Bauer
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

import collections
import enum

from x509sak.Exceptions import InvalidCAIndexFileEntry

class CertificateStatus(enum.Enum):
	Valid = "V"
	Revoked = "R"
	Expired = "E"

class OpenSSLCAIndexFile(object):
	_CertificateIndexEntry = collections.namedtuple("ValidCertificateIndexEntry", [ "status", "issuing_ts", "revocation_ts", "serial", "crt_filename", "dn" ])

	def __init__(self, filename):
		self._entries = [ ]
		self._entries_by_dn = collections.defaultdict(list)
		self._parse(filename)

	def _add_entry(self, entry):
		self._entries.append(entry)
		self._entries_by_dn[entry.dn].append(entry)

	def _parseline(self, line):
		line = line.split("\t")
		if len(line) != 6:
			raise InvalidCAIndexFileEntry("%s elements found in line, expected 6." % (len(line)))
		status_str = line[0]
		try:
			status = CertificateStatus(status_str)
		except ValueError:
			raise InvalidCAIndexFileEntry("Not a valid status identifier: %s" % (status_str))

		if status == CertificateStatus.Valid:
			entry = self._CertificateIndexEntry(status = status, issuing_ts = line[1], revocation_ts = None, serial = line[3], crt_filename = line[4], dn = line[5])
		elif status == CertificateStatus.Revoked:
			entry = self._CertificateIndexEntry(status = status, issuing_ts = line[1], revocation_ts = line[2], serial = line[3], crt_filename = line[4], dn = line[5])
		elif status == CertificateStatus.Expired:
			entry = self._CertificateIndexEntry(status = status, issuing_ts = line[1], revocation_ts = None, serial = line[3], crt_filename = line[4], dn = line[5])
		else:
			raise InvalidCAIndexFileEntry("Invalid combination of %s status line with %d elements total." % (status.name, len(line)))
		self._add_entry(entry)

	def _parse(self, filename):
		with open(filename) as f:
			for (lineno, line) in enumerate(f, 1):
				line = line.rstrip("\r\n")
				self._parseline(line)

	def write(self, filename):
		with open(filename, "w") as f:
			for entry in self._entries:
				fields = [ entry.status.value, entry.issuing_ts, entry.revocation_ts or "", entry.serial, entry.crt_filename, entry.dn ]
				print("\t".join(fields), file = f)

	def dump(self):
		print("CA index file has %d entries:" % (len(self._entries)))
		for entry in self._entries:
			print("   %s" % (str(entry)))
		print()
