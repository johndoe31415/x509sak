import setuptools

with open("README.md") as f:
	long_description = f.read()

setuptools.setup(
	name = "x509sak",
	packages = setuptools.find_packages(),
	version = "0.0.2",
	license = "gpl-3.0",
	description = "X.509 Swiss Army Knife is a toolkit atop OpenSSL to ease generation of CAs and aid white-hat pentesting",
	long_description = long_description,
	long_description_content_type = "text/markdown",
	author = "Johannes Bauer",
	author_email = "joe@johannes-bauer.com",
	url = "https://github.com/johndoe31415/x509sak",
	download_url = "https://github.com/johndoe31415/x509sak/archive/v0.0.2.tar.gz",
	keywords = [ "x509", "certificate", "toolkit", "openssl", "pki", "pentesting", "pkcs11", "ca" ],
	install_requires = [
		"pyasn1",
		"pyasn1_modules",
	],
	entry_points = {
		"console_scripts": [
			"x509sak = x509sak.__main__:main"
		]
	},
	include_package_data = True,
	classifiers = [
		"Development Status :: 5 - Production/Stable",
		"Intended Audience :: Developers",
		"License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
		"Programming Language :: Python :: 3",
		"Programming Language :: Python :: 3 :: Only",
		"Programming Language :: Python :: 3.5",
		"Programming Language :: Python :: 3.6",
		"Programming Language :: Python :: 3.7",
		"Programming Language :: Python :: 3.8",
		"Programming Language :: Python :: 3.9",
	],
)
