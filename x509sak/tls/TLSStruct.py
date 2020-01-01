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

import re
import inspect
import collections
from x509sak.Exceptions import ProgrammerErrorException, InvalidInputException

class TLSStruct():
	_Handlers = None
	_HandlerPurpose = collections.namedtuple("Purpose", [ "function", "typename_regex" ])

	def __init__(self, members, name = None):
		if self._Handlers is None:
			TLSStruct._Handlers = self._initialize_handlers()
		self._required_keys = set(key for (key, value) in members)
		if len(self._required_keys) != len(members):
			raise ProgrammerErrorException("Structure definition amgiguous, duplicate member names used.")
		self._members = collections.OrderedDict(members)
		self._name = name

	def _initialize_handlers(self):
		handlers = {
			"pack": [ ],
			"unpack": [ ],
		}
		self._UnpackHandlers = { }
		for (method_name, method) in inspect.getmembers(self, inspect.ismethod):
			signature = inspect.signature(method)
			anno = signature.return_annotation
			if (anno is not None) and (anno != inspect.Signature.empty):
				functions = (anno.function, ) if isinstance(anno.function, str) else anno.function
				typename_regex = anno.typename_regex
				compiled_typename_regex = re.compile(typename_regex)
				for function in functions:
					handlers[function].append((compiled_typename_regex, method))
		return handlers

	@property
	def name(self):
		return self._name

	@property
	def members(self):
		return iter(self._members.items())

	@classmethod
	def _get_handler(cls, function, typename):
		for (regex, method) in cls._Handlers[function]:
			match = regex.fullmatch(typename)
			if match:
				match = match.groupdict()
				return lambda x: method(match, x)
		raise ProgrammerErrorException("No %s handler for type '%s' found." % (function, typename))

	@classmethod
	def _call_handler(cls, function, typename, value):
		handler = cls._get_handler(function, typename)
		return handler(value)

	@classmethod
	def _unpack_int(cls, typename, databuffer) -> _HandlerPurpose(function = "unpack", typename_regex = r"uint(?P<bit>\d+)"):
		length_bits = int(typename["bit"])
		assert((length_bits % 8) == 0)
		length = length_bits // 8
		data = databuffer.get(length)
		return int.from_bytes(data, byteorder = "big")

	@classmethod
	def _pack_int(cls, typename, value) -> _HandlerPurpose(function = "pack", typename_regex = r"uint(?P<bit>\d+)"):
		length_bits = int(typename["bit"])
		assert((length_bits % 8) == 0)
		length = length_bits // 8
		minval = 0
		maxval = (1 << (length_bits)) - 1
		if (value < minval) or (value > maxval):
			raise InvalidInputException("%s must be between %d and %d (given value was %d)." % (typename, minval, maxval, value))
		data = int.to_bytes(value, byteorder = "big", length = length)
		return data

	@classmethod
	def _unpack_opaque(cls, typename, databuffer) -> _HandlerPurpose(function = "unpack", typename_regex = r"opaque(?P<bit>\d+)"):
		length = cls._call_handler("unpack", "uint" + typename["bit"], databuffer)
		return databuffer.get(length)

	@classmethod
	def _pack_opaque(cls, typename, data) -> _HandlerPurpose(function = "pack", typename_regex = r"opaque(?P<bit>\d+)"):
		return cls._call_handler("pack", "uint" + typename["bit"], len(data)) + data

	@classmethod
	def _unpack_array(cls, typename, databuffer) -> _HandlerPurpose(function = "unpack", typename_regex = r"array\[(?P<length>\d+)(,\s+(?P<padbyte>[0-9a-fA-F]{2}))?\]"):
		length = cls._call_handler("unpack", "uint" + typename["bit"], databuffer)
		return databuffer.get(length)

	@classmethod
	def _pack_array(cls, typename, data) -> _HandlerPurpose(function = "pack", typename_regex = r"array\[(?P<length>\d+)(,\s+(?P<padbyte>[0-9a-fA-F]{2}))?\]"):
		length = int(typename["length"])
		padbyte = None if (typename["padbyte"] is None) else int(typename["padbyte"], 16)

		if padbyte is None:
			# Size must exactly match up
			if len(data) == length:
				return data
			else:
				raise InvalidInputException("For packing of array of length %d without padding, %d bytes must be provided. Got %d bytes." % (length, length, len(data)))
		else:
			# Can pad
			if len(data) <= length:
				pad_len = length - len(data)
				padding = bytes([ padbyte ]) * pad_len
				return data + padding
			else:
				raise InvalidInputException("For packing of array of length %d with padding, at most %d bytes must be provided. Got %d bytes." % (length, length, len(data)))

	def pack(self, values):
		# First check if all members are present
		present_keys = set(values.keys())
		missing_keys = self._required_keys - present_keys
		if len(missing_keys) > 0:
			raise ProgrammerErrorException("Missing keys in %s: %s" % (self.__class__.__name__, ", ".join(sorted(missing_keys))))

		result_data = bytearray()
		for (membername, typename) in self.members:
			value = values[membername]
			result_data += self._call_handler("pack", typename, value)
		return bytes(result_data)

	def unpack(self, databuffer):
		result = { }
		with databuffer.rewind_on_exception():
			for (membername, typename) in self.members:
				result[membername] = self._call_handler("unpack", typename, databuffer)
			return result

	def __str__(self):
		return "%s<%s>" % (self.name, ", ".join(("%s %s" % (membername, typename) for (membername, typename) in self.members)))
