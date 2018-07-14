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

import os
import sys
import logging
import traceback
from x509sak.actions.ActionBuildChain import ActionBuildChain
from x509sak.actions.ActionGraphPool import ActionGraphPool
from x509sak.actions.ActionFindCert import ActionFindCert
from x509sak.actions.ActionCreateCA import ActionCreateCA
from x509sak.actions.ActionCreateCSR import ActionCreateCSR
from x509sak.actions.ActionSignCSR import ActionSignCSR
from x509sak.actions.ActionRevokeCRT import ActionRevokeCRT
from x509sak.actions.ActionGenerateBrokenRSA import ActionGenerateBrokenRSA
from x509sak.actions.ActionDumpKey import ActionDumpKey
from x509sak.actions.ActionForgeCert import ActionForgeCert
from x509sak.CmdLineArgs import KeySpecArgument, KeyValue
from x509sak.KeySpecification import KeySpecification
from x509sak.Exceptions import UserErrorException, InvisibleUserErrorException
from .FriendlyArgumentParser import baseint
from .MultiCommand import MultiCommand
from x509sak.SubprocessExecutor import SubprocessExecutor

if "X509SAK_VERBOSE_EXECUTION" in os.environ:
	SubprocessExecutor.set_verbose()
if "X509SAK_PAUSE_FAILED_EXECUTION" in os.environ:
	SubprocessExecutor.pause_after_failed_execution()
if "X509SAK_PAUSE_BEFORE_EXECUTION" in os.environ:
	SubprocessExecutor.pause_before_execution()

def __keyspec(arg):
	keyspec_arg = KeySpecArgument(arg)
	return KeySpecification.from_keyspec_argument(keyspec_arg)

mc = MultiCommand()

def genparser(parser):
	parser.add_argument("-s", "--ca-source", metavar = "path", action = "append", default = [ ], help = "CA file (PEM format) or directory (containing .pem/.crt files) to include when building the chain. Can be specified multiple times to include multiple locations.")
	parser.add_argument("--inform", choices = [ "pem", "der" ], default = "pem", help = "Specifies input file format for certificate. Possible options are %(choices)s. Default is %(default)s.")
	parser.add_argument("--order-leaf-to-root", action = "store_true", help = "By default, certificates are ordered with the root CA first and intermediate certificates following up to the leaf. When this option is specified, the order is inverted and go from leaf certificate to root.")
	parser.add_argument("--allow-partial-chain", action = "store_true", help = "When building the certificate chain, a full chain must be found or the chain building fails. When this option is specified, also partial chain matches are permitted, i.e., not going up to a root CA. Note that this can have undesired side effects when no root certificates are found at all (the partial chain will then consist of only the leaf certificate itself).")
	parser.add_argument("--dont-trust-crtfile", action = "store_true", help = "When there's multiple certificates in the given crtfile in PEM format, they're by default all added to the truststore. With this option, only the leaf cert is taken from the crtfile and they're not added to the trusted pool.")
	parser.add_argument("--outform", choices = [ "rootonly", "intermediates", "fullchain", "all-except-root", "multifile" ], default = "fullchain", help = "Specifies what to write into the output file. Possible options are %(choices)s. Default is %(default)s. When specifying multifile, a %%d format must be included in the filename to serve as a template; typical printf-style formatting can be used of course (e.g., %%02d).")
	parser.add_argument("-o", "--outfile", metavar = "file", help = "Specifies the output filename. Defaults to stdout.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("crtfile", metavar = "crtfile", type = str, help = "Certificate that a chain shall be build for, in PEM format.")
mc.register("buildchain", "Build a certificate chain", genparser, action = ActionBuildChain, aliases = [ "bc" ])

def genparser(parser):
	parser.add_argument("-f", "--format", choices = [ "dot", "png", "ps", "pdf" ], default = None, help = "Specifies the output file format. Can be one of %(choices)s, defaults to %(default)s. When unspecified, the file extension out the output file is used to determine the file type.")
	parser.add_argument("-o", "--outfile", metavar = "file", required = True, help = "Specifies the output filename. Mandatory argument.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("crtsource", metavar = "crtsource", nargs = "+", type = str, help = "Certificate file (in PEM format) or directory (conainting PEM-formatted .pem or .crt files) which should be included in the graph.")
mc.register("graph", "Graph a certificate pool", genparser, action = ActionGraphPool)

def genparser(parser):
	parser.add_argument("-h", "--hashval", metavar = "hash", type = str, help = "Find only certificates with a particular hash prefix.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("crtsource", metavar = "crtsource", nargs = "+", type = str, help = "Certificate file (in PEM format) or directory (conainting PEM-formatted .pem or .crt files) which should be included in the search.")
mc.register("findcrt", "Find a specific certificate", genparser, action = ActionFindCert)

def genparser(parser):
	parser.add_argument("-k", "--keytype", metavar = "keyspec", type = __keyspec, default = "ecc:secp384r1", help = "Private key type to generate for the new CA. Defaults to %(default)s. Keyspecs have the form cryptosystem:args, where cryptosystem can be any of rsa, ecc or hw and the args depend on the cryptosystem; for RSA, it's the bitlength, for ECC, it's the curve name and for HW it's the key ID of the hardware token key. Examples are rsa:1024, ecc:secp256r1 or hw:1.")
	parser.add_argument("-p", "--parent-ca", metavar = "capath", type = str, help = "Parent CA directory. If omitted, CA certificate will be self-signed.")
	parser.add_argument("-s", "--subject-dn", metavar = "subject", type = str, default = "/CN=Root CA", help = "CA subject distinguished name. Defaults to %(default)s.")
	parser.add_argument("-d", "--validity-days", metavar = "days", type = int, default = 365, help = "Number of days that the newly created CA will be valid for. Defaults to %(default)s days.")
	parser.add_argument("-h", "--hashfnc", metavar = "alg", type = str, default = "sha256", help = "Hash function to use for signing. Defaults to %(default)s.")
	parser.add_argument("--serial", metavar = "serial", type = baseint, help = "Serial number to use for root CA certificate. Randomized by default.")
	parser.add_argument("-f", "--force", action = "store_true", help = "By default, the capath will not be overwritten if it already exists. When this option is specified the complete directory will be erased before creating the new CA.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("capath", metavar = "capath", type = str, help = "Directory to create the new CA in.")
mc.register("createca", "Create a new certificate authority (CA)", genparser, action = ActionCreateCA)

def genparser(parser):
	parser.add_argument("-k", "--keytype", metavar = "keyspec", type = __keyspec, help = "Private key type to generate for the certificate or CSR. By default, it is assumed the private key has created beforehand. Keyspecs have the form cryptosystem:args, where cryptosystem can be any of rsa, ecc or hw and the args depend on the cryptosystem; for RSA, it's the bitlength, for ECC, it's the curve name and for HW it's the key ID of the hardware token key. Examples are rsa:1024, ecc:secp256r1 or hw:1.")
	parser.add_argument("-t", "--template", choices = [ "rootca", "ca", "tls-server", "tls-client" ], help = "Template to use for determining X.509 certificate extensions. Can be one of %(choices)s. By default, no extensions are included except for SAN.")
	parser.add_argument("-s", "--subject-dn", metavar = "subject", type = str, default = "/CN=New Cert", help = "Certificate/CSR subject distinguished name. Defaults to %(default)s.")
	parser.add_argument("-d", "--validity-days", metavar = "days", type = int, default = 365, help = "When creating a certificate, number of days that the certificate will be valid for. Defaults to %(default)s days.")
	parser.add_argument("-h", "--hashfnc", metavar = "alg", type = str, default = None, help = "Hash function to use for signing when creating a certificate. Defaults to the default hash function specified in the CA config.")
	parser.add_argument("--san-dns", metavar = "FQDN", type = str, action = "append", default = [ ], help = "Subject Alternative DNS name to include in the certificate or CSR. Can be specified multiple times.")
	parser.add_argument("--san-ip", metavar = "IP", type = str, action = "append", default = [ ], help = "Subject Alternative IP address to include in the certificate or CSR. Can be specified multiple times.")
	parser.add_argument("--extension", metavar = "key=value", type = KeyValue, action = "append", default = [ ], help = "Additional certificate X.509 extension to include on top of the extensions in the template and by the SAN parameters. Can be specified multiple times.")
	parser.add_argument("-f", "--force", action = "store_true", help = "Overwrite the output file if it already exists.")
	parser.add_argument("-c", "--create-crt", metavar = "capath", help = "Instead of creating a certificate signing request, directly create a certificate instead. Needs to supply the CA path that should issue the certificate.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("key_filename", metavar = "in_key_filename", type = str, help = "Filename of the input private key.")
	parser.add_argument("out_filename", metavar = "out_filename", type = str, help = "Filename of the output certificate signing request or certificate.")
mc.register("createcsr", "Create a new certificate signing request (CSR) or certificate", genparser, action = ActionCreateCSR)

def genparser(parser):
	parser.add_argument("-t", "--template", choices = [ "rootca", "ca", "tls-server", "tls-client" ], help = "Template to use for determining X.509 certificate extensions. Can be one of %(choices)s. By default, no extensions are included except for SAN.")
	parser.add_argument("-s", "--subject-dn", metavar = "subject", type = str, help = "Certificate's subject distinguished name. Defaults to the subject given in the CSR.")
	parser.add_argument("--san-dns", metavar = "FQDN", type = str, action = "append", default = [ ], help = "Subject Alternative DNS name to include in the certificate. Can be specified multiple times.")
	parser.add_argument("--san-ip", metavar = "IP", type = str, action = "append", default = [ ], help = "Subject Alternative IP address to include in the CRT. Can be specified multiple times.")
	parser.add_argument("-d", "--validity-days", metavar = "days", type = int, default = 365, help = "Number of days that the newly created certificate will be valid for. Defaults to %(default)s days.")
	parser.add_argument("-h", "--hashfnc", metavar = "alg", type = str, default = None, help = "Hash function to use for signing. Defaults to the default hash function specified in the CA config.")
	parser.add_argument("-f", "--force", action = "store_true", help = "Overwrite the output certificate file if it already exists.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("capath", metavar = "capath", type = str, help = "Directory of the signing CA.")
	parser.add_argument("csr_filename", metavar = "in_csr_filename", type = str, help = "Filename of the input certificate signing request.")
	parser.add_argument("crt_filename", metavar = "out_crt_filename", type = str, help = "Filename of the output certificate.")
mc.register("signcsr", "Make a certificate authority (CA) sign a crtificate signing request (CSR) and output the certificate", genparser, action = ActionSignCSR)

def genparser(parser):
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("capath", metavar = "capath", type = str, help = "CA which created the certificate.")
	parser.add_argument("crt_filename", metavar = "crt_filename", type = str, help = "Filename of the output certificate.")
mc.register("revokecrt", "Revoke a specific certificate", genparser, action = ActionRevokeCRT)

def genparser(parser):
	parser.add_argument("-d", "--prime-db", metavar = "path", type = str, default = ".", help = "Prime database directory. Defaults to %(default)s and searches for files called primes_{bitlen}.txt in this directory.")
	parser.add_argument("-b", "--bitlen", metavar = "bits", type = int, default = 2048, help = "Bitlength of primes p/q to choose. Note that the modulus bitlength will be twice of that because it is the product of two primes (n = pq). Defaults to %(default)d bits.")
	parser.add_argument("-e", "--public-exponent", metavar = "exp", type = int, default = 0x10001, help = "Public exponent e (or d in case --switch-e-d is specified) to use. Defaults to 0x%(default)x. Will be randomly chosen from 2..n-1 if set to -1.")
	parser.add_argument("--switch-e-d", action = "store_true", help = "Swtich e with d when generating keypair.")
	parser.add_argument("--accept-unusable-key", action = "store_true", help = "Disregard integral checks, such as if gcd(e, phi(n)) == 1 before inverting e. Might lead to an unusable key or might fail altogether.")
	parser.add_argument("--close-q", action = "store_true", help = "Use a value for q that is very close to the value of p so that search starting from sqrt(n) is computationally feasible to factor the modulus.")
	parser.add_argument("-o", "--outfile", metavar = "file", type = str, default = "broken_rsa.key", help = "Output filename. Defaults to %(default)s.")
	parser.add_argument("-f", "--force", action = "store_true", help = "Overwrite output file if it already exists instead of bailing out.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
mc.register("genbrokenrsa", "Generate broken RSA keys for use in pentetration testing", genparser, action = ActionGenerateBrokenRSA)

def genparser(parser):
	parser.add_argument("-t", "--key-type", choices = [ "rsa", "ecc" ], default = "rsa", help = "Type of private key to import. Can be one of %(choices)s, defaults to %(default)s. Disregarded for public keys and determined automatically.")
	parser.add_argument("-p", "--public-key", action = "store_true", help = "Input is a public key, not a private key.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("key_filename", metavar = "key_filename", type = str, help = "Filename of the input key file in PEM format.")
mc.register("dumpkey", "Dump a key in text form", genparser, action = ActionDumpKey)

def genparser(parser):
	parser.add_argument("--key_template", metavar = "path", default = "forged_%02d.key", help = "Output template for key files. Should contain '%%d' to indicate element in chain. Defaults to '%(default)s'.")
	parser.add_argument("--cert_template", metavar = "path", default = "forged_%02d.crt", help = "Output template for certificate files. Should contain '%%d' to indicate element in chain. Defaults to '%(default)s'.")
	parser.add_argument("-r", "--recalculate-keyids", action = "store_true", help = "By default, Subject Key Identifier and Authority Key Identifier X.509 extensions are kept as-is in the forged certificates. Specifying this will recalculate the IDs to fit the forged keys.")
	parser.add_argument("-f", "--force", action = "store_true", help = "Overwrite key/certificate files.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("crt_filename", metavar = "crt_filename", type = str, help = "Filename of the input certificate or certificates PEM format.")
mc.register("forgecert", "Forge an X.509 certificate", genparser, action = ActionForgeCert)

try:
	mc.run(sys.argv[1:])
except (UserErrorException, InvisibleUserErrorException) as e:
	if logging.root.level == logging.DEBUG:
		traceback.print_exc()
		print()
	if isinstance(e, UserErrorException) or (logging.root.level == logging.DEBUG):
		print("%s: %s" % (e.__class__.__name__, str(e)))
	sys.exit(1)
