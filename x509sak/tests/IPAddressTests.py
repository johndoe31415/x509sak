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

from x509sak.tests import BaseTest
from x509sak.IPAddress import IPAddress, IPAddressSubnet
from x509sak.Exceptions import InvalidIPAddressException

class IPAddressTests(BaseTest):
	def test_ipv4(self):
		ip = IPAddress(bytes.fromhex("aa bb cc dd"))
		self.assertEqual(str(ip), "170.187.204.221")
		self.assertEqual(int(ip), 0xaabbccdd)

	def test_ipv6(self):
		ip = IPAddress(bytes.fromhex("aa bb cc dd 1a 1b 1c 1d 2a 2b 2c 2d 3a 3b 3c 3d"))
		self.assertEqual(str(ip), "aabb:ccdd:1a1b:1c1d:2a2b:2c2d:3a3b:3c3d")
		self.assertEqual(int(ip), 0xaabbccdd1a1b1c1d2a2b2c2d3a3b3c3d)

	def test_ipv6_shortlead(self):
		ip = IPAddress(bytes.fromhex("01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 00 0f"))
		self.assertEqual(str(ip), "102:304:506:708:90a:b0c:d0e:f")

	def test_ipv6_shortabbr1(self):
		ip = IPAddress(bytes.fromhex("1122 3344 0000 0000 0000 0000 0000 5566"))
		self.assertEqual(str(ip), "1122:3344::5566")

	def test_ipv6_shortabbr2(self):
		ip = IPAddress(bytes.fromhex("1122 0000 3344 0000 0000 0000 0000 5566"))
		self.assertEqual(str(ip), "1122::3344:0:0:0:0:5566")

	def test_ipv6_shortabbr3(self):
		ip = IPAddress(bytes.fromhex("0000 0000 0000 0000 0000 0000 0000 5566"))
		self.assertEqual(str(ip), "::5566")

	def test_ipv6_shortabbr4(self):
		ip = IPAddress(bytes.fromhex("1122 0000 0000 0000 0000 0000 0000 5566"))
		self.assertEqual(str(ip), "1122::5566")

	def test_ipv6_shortabbr5(self):
		ip = IPAddress(bytes.fromhex("1122 0000 0000 0000 0000 0000 0000 0000"))
		self.assertEqual(str(ip), "1122::")

	def test_ipv6_shortabbr6(self):
		ip = IPAddress(bytes.fromhex("0000 0000 0000 0000 0000 0000 0000 0000"))
		self.assertEqual(str(ip), "::")

	def test_malformed(self):
		with self.assertRaises(InvalidIPAddressException):
			IPAddress(bytes.fromhex("aa bb cc"))

	def test_subnet(self):
		subnet = IPAddressSubnet.from_bytes(bytes.fromhex("aa bb cc 00 ff ff ff 00"))
		self.assertEqual(str(subnet), "170.187.204.0/24")

	def test_subnet_overlap(self):
		subnet = IPAddressSubnet.from_bytes(bytes.fromhex("aa bb cc 00 ff ff aa 00"))
		self.assertEqual(str(subnet), "170.187.204.0/255.255.170.0")

	def test_subnet_noncidr(self):
		subnet = IPAddressSubnet.from_bytes(bytes.fromhex("aa bb 00 cc ff ff 00 ff"))
		self.assertEqual(str(subnet), "170.187.0.204/255.255.0.255")

	def test_subnet_full(self):
		subnet = IPAddressSubnet.from_bytes(bytes.fromhex("01 02 03 04 ff ff ff ff"))
		self.assertEqual(str(subnet), "1.2.3.4")

	def test_subnet_empty(self):
		subnet = IPAddressSubnet.from_bytes(bytes.fromhex("aa bb cc dd 00 00 00 00"))
		self.assertEqual(str(subnet), "170.187.204.221/0.0.0.0")

	def test_subnet_malformed(self):
		with self.assertRaises(InvalidIPAddressException):
			IPAddressSubnet(IPAddress(range(4)), IPAddress(range(16)))

	def test_subnet_parse(self):
		subnet = IPAddressSubnet.from_str("192.168.1.0/24")
		self.assertEqual(str(subnet.ip), "192.168.1.0")
		self.assertEqual(str(subnet.subnet), "255.255.255.0")

		subnet = IPAddressSubnet.from_str("192.168.1.0/255.255.255.0")
		self.assertEqual(str(subnet), "192.168.1.0/24")

	def test_cidr_create_ipv4(self):
		self.assertEqual(str(IPAddress.create_cidr_subnet(32)), "255.255.255.255")
		self.assertEqual(str(IPAddress.create_cidr_subnet(24)), "255.255.255.0")
		self.assertEqual(str(IPAddress.create_cidr_subnet(16)), "255.255.0.0")
		self.assertEqual(str(IPAddress.create_cidr_subnet(10)), "255.192.0.0")
		self.assertEqual(str(IPAddress.create_cidr_subnet(8)), "255.0.0.0")
		self.assertEqual(str(IPAddress.create_cidr_subnet(1)), "128.0.0.0")
		self.assertEqual(str(IPAddress.create_cidr_subnet(0)), "0.0.0.0")
