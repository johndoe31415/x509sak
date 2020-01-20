#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2020-2020 Johannes Bauer
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

from x509sak.Exceptions import InvalidIPAddressException

class IPAddress():
	def __init__(self, bytes_data):
		self._data = bytes(bytes_data)
		if len(self._data) not in [ 4, 16 ]:
			raise InvalidIPAddressException("Data with length %d is neither IPv4 nor IPv6 address." % (len(self._data)))

	@property
	def is_ipv4(self):
		return len(self._data) == 4

	@property
	def ipv6_chunks(self):
		return (((self._data[i] << 8) | self._data[i + 1]) for i in range(0, 16, 2))

	@classmethod
	def from_str(cls, ip_str):
		return cls(bytes(int(x) for x in ip_str.split(".")))

	@classmethod
	def create_cidr_subnet(cls, network_bits, is_ipv4 = True):
		bits_total = 32 if is_ipv4 else 128
		assert(0 <= network_bits <= bits_total)
		all_bits = (1 << bits_total) - 1
		variable_mask = (1 << (32 - network_bits)) - 1
		cidr_mask = all_bits & (~variable_mask)
		cidr_data = int.to_bytes(cidr_mask, length = bits_total // 8, byteorder = "big")
		return cls(cidr_data)

	def __bytes__(self):
		return self._data

	def __int__(self):
		return int.from_bytes(self._data, byteorder = "big")

	def __len__(self):
		return len(self._data)

	def __str__(self):
		if self.is_ipv4:
			return ".".join(str(x) for x in self._data)
		else:
			abbreviation = None
			string = [ ]
			for chunk in self.ipv6_chunks:
				if (chunk != 0) or (abbreviation is False):
					string.append("%x" % (chunk))
					if abbreviation is True:
						abbreviation = False
				else:
					if abbreviation is None:
						# Start to abbreviate now
						abbreviation = True
						string.append("")

			if string == [ "" ]:
				string.append(":")
			elif string[0] == "":
				string.insert(0, "")
			elif string[-1] == "":
				string.append("")
			return ":".join(string)

class IPAddressSubnet():
	def __init__(self, ip, subnet):
		self._ip = ip
		self._subnet = subnet
		if self.ip.is_ipv4 != self.subnet.is_ipv4:
			raise InvalidIPAddressException("Network address and subnet mask must be same IP protocol, cannot mix IPv4 with IPv6.")
		self._overlap = (int(self._ip) & int(self._subnet)) != int(self._ip)
		if not self._overlap:
			# Well-formed network/subnet
			self._cidr = self._calculate_cidr(self._subnet)
		else:
			# Don't create a CIDR address if there's any ambiguity
			self._cidr = None

	@staticmethod
	def _calculate_cidr(mask):
		mask_val = int(mask)
		mask_bits = len(mask) * 8
		zero_bits = 0
		for i in range(mask_bits):
			if (mask_val & 1) == 0:
				zero_bits += 1
				mask_val >>= 1
			else:
				break

		full_mask = (1 << mask_bits) - 1
		cidr_mask = full_mask & (~((1 << zero_bits) - 1))
		if cidr_mask == int(mask):
			return mask_bits - zero_bits
		else:
			return None

	@property
	def is_ipv4(self):
		return self.ip.is_ipv4

	@property
	def ip(self):
		return self._ip

	@property
	def subnet(self):
		return self._subnet

	@property
	def is_cidr(self):
		return (self._cidr is not None)

	@property
	def cidr(self):
		return self._cidr

	@property
	def overlap(self):
		return self._overlap

	@classmethod
	def from_str(cls, ip_subnet_str):
		ip_subnet = ip_subnet_str.split("/")
		ip  = IPAddress.from_str(ip_subnet[0])
		try:
			network_bits = int(ip_subnet[1])
			subnet = IPAddress.create_cidr_subnet(network_bits, is_ipv4 = ip.is_ipv4)
		except ValueError:
			subnet = IPAddress.from_str(ip_subnet[1])
		return cls(ip, subnet)

	@classmethod
	def from_bytes(cls, ip_subnet_data, allow_ip_only = False):
		ip_subnet_data = bytes(ip_subnet_data)
		if allow_ip_only and (len(ip_subnet_data) in [ 4, 16 ]):
			return IPAddress(ip_subnet_data)

		mid = len(ip_subnet_data) // 2
		ip = ip_subnet_data[:mid]
		subnet = ip_subnet_data[mid:]
		return cls(ip = IPAddress(ip), subnet = IPAddress(subnet))

	def ip_in_subnet(self, ip):
		if ip.is_ipv4 != self.is_ipv4:
			return False
		self_network = int(self.ip) & int(self.subnet)
		ip_network = int(ip) & int(self.subnet)
		return self_network == ip_network

	def __str__(self):
		cidr = self.cidr
		if cidr is None:
			return "%s/%s" % (self.ip, self.subnet)
		else:
			if cidr == (len(self.subnet) * 8):
				return str(self.ip)
			else:
				return "%s/%d" % (self.ip, cidr)

