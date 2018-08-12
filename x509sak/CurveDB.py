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

from x509sak.Tools import JSONTools
from x509sak.OID import OID
from x509sak.Exceptions import LazyDeveloperException, CurveNotFoundException
from x509sak.ECCMath import PrimeFieldEllipticCurve, BinaryFieldEllipticCurve

class CurveDB(object):
	_DB_DATA = None
	_OID_BY_NAME = None

	def __init__(self):
		if self._DB_DATA is None:
			self._DB_DATA = self._load_db_data()
		if self._OID_BY_NAME is None:
			self._OID_BY_NAME = { curve["name"]: oid for (oid, curve) in self._DB_DATA.items() }

	@staticmethod
	def _load_db_data():
		json_data = JSONTools.load_internal("x509sak.data.ecc", "curves.json")
		return { OID.from_str(oid): parameters for (oid, parameters) in json_data.items() }

	def lookup(self, oid = None, name = None, on_error = "none"):
		# Either OID or name must be given, not both
		assert((oid is not None) ^ (name is not None))
		assert((oid is None) or isinstance(oid, OID))
		assert((name is None) or isinstance(name, str))
		assert(on_error in [ "none", "raise" ])

		if oid is not None:
			curve_data = self._DB_DATA.get(oid)
		else:
			curve_data = self._DB_DATA.get(self._OID_BY_NAME.get(name))
		if (curve_data is None) and (on_error == "raise"):
			if oid is not None:
				raise CurveNotFoundException("No such curve with OID %s in database." % (oid))
			else:
				raise CurveNotFoundException("No such curve with name %s in database." % (name))
		return curve_data

	def instanciate(self, oid = None, name = None):
		curve_data = self.lookup(oid = oid, name = name, on_error = "raise")

		domain = curve_data["domain"]
		if curve_data["field"] == "prime":
			return PrimeFieldEllipticCurve(**domain)
		elif curve_data["field"] == "binary":
			return BinaryFieldEllipticCurve(**domain)
		else:
			raise LazyDeveloperException(NotImplemented, curve_data["field"])

	def __iter__(self):
		return iter(self._DB_DATA)
