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

from x509sak.tests import BaseTest
from x509sak.Tools import ValidationTools

class ValidationToolsTests(BaseTest):
	def test_emails_valid(self):
		self.assertTrue(ValidationTools.validate_email_address("foo@bar.de"))
		self.assertTrue(ValidationTools.validate_email_address("x@y"))
		self.assertTrue(ValidationTools.validate_email_address("x@d.y"))
		self.assertTrue(ValidationTools.validate_email_address("x@a.d.y"))
		self.assertTrue(ValidationTools.validate_email_address("0@a.d.y"))
		self.assertTrue(ValidationTools.validate_email_address("foo@bar.co.uk"))
		self.assertTrue(ValidationTools.validate_email_address("foo.bar@bar.co.uk"))
		self.assertTrue(ValidationTools.validate_email_address("foo_bar@bar.co.uk"))

	def test_emails_invalid(self):
		self.assertFalse(ValidationTools.validate_email_address(""))
		self.assertFalse(ValidationTools.validate_email_address("@"))
		self.assertFalse(ValidationTools.validate_email_address("a"))
		self.assertFalse(ValidationTools.validate_email_address("abc@"))
		self.assertFalse(ValidationTools.validate_email_address("@abc"))
		self.assertFalse(ValidationTools.validate_email_address("abc@.abc"))
		self.assertFalse(ValidationTools.validate_email_address("abc@abc."))
		self.assertFalse(ValidationTools.validate_email_address("abc@ abc"))
		self.assertFalse(ValidationTools.validate_email_address("abc@ abc"))

	def test_domains_valid(self):
		self.assertTrue(ValidationTools.validate_domainname("bar.de"))
		self.assertTrue(ValidationTools.validate_domainname("y"))
		self.assertTrue(ValidationTools.validate_domainname("d.y"))
		self.assertTrue(ValidationTools.validate_domainname("a.d.y"))
		self.assertTrue(ValidationTools.validate_domainname("a.d.y"))
		self.assertTrue(ValidationTools.validate_domainname("bar.co.uk"))

	def test_domains_invalid(self):
		self.assertFalse(ValidationTools.validate_domainname(""))
		self.assertFalse(ValidationTools.validate_domainname("."))
		self.assertFalse(ValidationTools.validate_domainname(".foo"))
		self.assertFalse(ValidationTools.validate_domainname("foo."))
		self.assertFalse(ValidationTools.validate_domainname("foo bar"))

	def test_domains_invalid(self):
		self.assertFalse(ValidationTools.validate_domainname(""))
		self.assertFalse(ValidationTools.validate_domainname("."))
		self.assertFalse(ValidationTools.validate_domainname(".foo"))
		self.assertFalse(ValidationTools.validate_domainname("foo."))
		self.assertFalse(ValidationTools.validate_domainname("foo bar"))

	def test_uri_valid(self):
		self.assertFalse(ValidationTools.validate_uri("/foo/bar"))
		self.assertFalse(ValidationTools.validate_uri("moo.com/foobar"))
		self.assertFalse(ValidationTools.validate_uri("foo.de:80/jfisoud"))
		self.assertFalse(ValidationTools.validate_uri("://foo"))
		self.assertFalse(ValidationTools.validate_uri("://foo/"))

	def test_uri_valid(self):
		self.assertTrue(ValidationTools.validate_uri("http://a"))
		self.assertTrue(ValidationTools.validate_uri("http://a.a/"))
		self.assertTrue(ValidationTools.validate_uri("http://a/a"))
		self.assertTrue(ValidationTools.validate_uri("http://a/a/"))
		self.assertTrue(ValidationTools.validate_uri("http://a/a/?"))
		self.assertTrue(ValidationTools.validate_uri("http://a/a/?a"))
		self.assertTrue(ValidationTools.validate_uri("http://de.wikipedia.org/wiki/Uniform_Resource_Identifier"))
		self.assertTrue(ValidationTools.validate_uri("http://de.wikipedia.org/wiki/Uniform_Resource_Identifier/"))
		self.assertTrue(ValidationTools.validate_uri("ftp://ftp.is.co.za/rfc/rfc1808.txt"))
		self.assertTrue(ValidationTools.validate_uri("file:///C:/Users/Benutzer/Desktop/Uniform%20Resource%20Identifier.html"))
		self.assertTrue(ValidationTools.validate_uri("file:///etc/fstab"))
		self.assertTrue(ValidationTools.validate_uri("geo:48.33,14.122;u=22.5"))
		self.assertTrue(ValidationTools.validate_uri("ldap://[2001:db8::7]/c=GB?objectClass?one"))
		self.assertTrue(ValidationTools.validate_uri("gopher://gopher.floodgap.com"))
		self.assertTrue(ValidationTools.validate_uri("mailto:John.Doe@example.com"))
		self.assertTrue(ValidationTools.validate_uri("sip:911@pbx.mycompany.com"))
		self.assertTrue(ValidationTools.validate_uri("news:comp.infosystems.www.servers.unix"))
		self.assertTrue(ValidationTools.validate_uri("data:text/plain;charset=iso-8859-7,%be%fa%be"))
		self.assertTrue(ValidationTools.validate_uri("tel:+1-816-555-1212"))
		self.assertTrue(ValidationTools.validate_uri("telnet://192.0.2.16:80/"))
		self.assertTrue(ValidationTools.validate_uri("urn:oasis:names:specification:docbook:dtd:xml:4.1.2"))
		self.assertTrue(ValidationTools.validate_uri("git://github.com/rails/rails.git"))
		self.assertTrue(ValidationTools.validate_uri("crid://broadcaster.com/movies/BestActionMovieEver"))











