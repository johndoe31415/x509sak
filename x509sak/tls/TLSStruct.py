#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2019-2019 Johannes Bauer
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

import inspect
import collections
from x509sak.Exceptions import ProgrammerErrorException, InvalidInputException

class TLSStruct():
	_PackHandlers = None
	_UnpackHandlers = None
	_HandlerPurpose = collections.namedtuple("Purpose", [ "function", "typenames" ])

	def __init__(self, members, name = None):
		if self._PackHandlers is None:
			self._initialize_handlers()
		self._required_keys = set(key for (key, value) in members)
		assert(len(self._required_keys) == len(members))
		self._members = collections.OrderedDict(members)
		self._name = name

	def _initialize_handlers(self):
		self._PackHandlers = { }
		self._UnpackHandlers = { }
		for (method_name, method) in inspect.getmembers(self, inspect.ismethod):
			signature = inspect.signature(method)
			anno = signature.return_annotation
			if (anno is not None) and (anno != inspect.Signature.empty):
				functions = (anno.function, ) if isinstance(anno.function, str) else anno.function
				typenames = (anno.typenames, ) if isinstance(anno.typenames, str) else anno.typenames
				for function in functions:
					for typename in typenames:
						if function == "pack":
							self._PackHandlers[typename] = method
						elif function == "unpack":
							self._UnpackHandlers[typename] = method
						else:
							raise NotImplementedError(function)

	@property
	def name(self):
		return self._name

	@property
	def members(self):
		return iter(self._members.items())

	@classmethod
	def _unpack_int(cls, typename, databuffer) -> _HandlerPurpose(function = "unpack", typenames = [ "u8", "u16", "u24" ]):
		length = int(typename[1:]) // 8
		data = databuffer.get(length)
		return int.from_bytes(data, byteorder = "big")

	@classmethod
	def _pack_int(cls, typename, value) -> _HandlerPurpose(function = "pack", typenames = [ "u8", "u16", "u24" ]):
		length_bits = int(typename[1:])
		length = length_bits // 8
		minval = 0
		maxval = (1 << (length_bits)) - 1
		if (value < minval) or (value > maxval):
			raise InvalidInputException("%s must be between %d and %d (given value was %d)." % (typename, minval, maxval, value))
		data = int.to_bytes(value, byteorder = "big", length = length)
		return data

	@classmethod
	def _unpack_opaque(cls, typename, databuffer) -> _HandlerPurpose(function = "unpack", typenames = [ "opaque8", "opaque16", "opaque24" ]):
		bitlen = typename[6:]
		length = cls._unpack_int("u" + bitlen, databuffer)
		return databuffer.get(length)

	def pack(self, values):
		# First check if all members are present
		present_keys = set(values.keys())
		missing_keys = self._required_keys - present_keys
		if len(missing_keys) > 0:
			raise ProgrammerErrorException("Missing keys in %s: %s" % (self.__class__.__name__, ", ".join(sorted(missing_keys))))

		result_data = bytearray()
		for (membername, typename) in self.members:
			value = values[membername]
			handler = self._PackHandlers[typename]
			result_data += handler(typename, value)
		return bytes(result_data)

	def unpack(self, databuffer):
		result = { }
		with databuffer.rewind_on_exception():
			for (membername, typename) in self.members:
				handler = self._UnpackHandlers[typename]
				result[membername] = handler(typename, databuffer)
			return result

	def __str__(self):
		return "%s<%s>" % (self.name, ", ".join(("%s %s" % (membername, typename) for (membername, typename) in self.members)))
