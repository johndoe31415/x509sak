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

from x509sak.Tools import JSONTools
from x509sak.OID import OID
from x509sak.Exceptions import LazyDeveloperException, CurveNotFoundException, InvalidInputException
from x509sak.ECCMath import PrimeFieldEllipticCurve, BinaryFieldEllipticCurve, TwistedEdwardsEllipticCurve

class CurveDB():
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
		result = { OID.from_str(oid): parameters for (oid, parameters) in json_data.items() }
		for (oid, parameters) in result.items():
			parameters["oid"] = oid
		return result

	def lookup(self, oid = None, name = None, on_error = "none"):
		assert(on_error in [ "none", "raise" ])

		# Check that either OID or name must be given, not both
		if (oid is None) and (name is None):
			raise InvalidInputException("Lookup from curve database needs either OID or name of curve to look up.")
		if (oid is not None) and (name is not None):
			raise InvalidInputException("Lookup from curve database needs either OID or name of curve to look up, not both. Given: OID %s and name %s." % (oid, name))

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
		metadata = {
			"name":		curve_data["name"],
			"oid":		curve_data["oid"],
		}
		if curve_data["curvetype"] == "prime":
			return PrimeFieldEllipticCurve(metadata = metadata, **domain)
		elif curve_data["curvetype"] == "binary":
			return BinaryFieldEllipticCurve(metadata = metadata, **domain)
		elif curve_data["curvetype"] == "twisted_edwards":
			return TwistedEdwardsEllipticCurve(metadata = metadata, **domain)
		else:
			raise LazyDeveloperException(NotImplemented, curve_data["curvetype"])

	def __iter__(self):
		return iter(self._DB_DATA)
