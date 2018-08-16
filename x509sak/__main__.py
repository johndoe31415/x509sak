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
from x509sak.actions.ActionCreateCRL import ActionCreateCRL
from x509sak.actions.ActionGenerateBrokenRSA import ActionGenerateBrokenRSA
from x509sak.actions.ActionDumpKey import ActionDumpKey
from x509sak.actions.ActionExamineCert import ActionExamineCert
from x509sak.actions.ActionForgeCert import ActionForgeCert
from x509sak.actions.ActionScrape import ActionScrape
from x509sak.CmdLineArgs import KeySpecArgument, KeyValue
from x509sak.KeySpecification import KeySpecification
from x509sak.Exceptions import UserErrorException, InvisibleUserErrorException, CmdExecutionFailedException
from x509sak.SubprocessExecutor import SubprocessExecutor
from .FriendlyArgumentParser import baseint, baseint_unit
from .MultiCommand import MultiCommand

_default_so_search_path = "/usr/local/lib:/usr/lib:/usr/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu/openssl-1.0.2/engines:/usr/lib/x86_64-linux-gnu/engines-1.1"

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
	parser.add_argument("--outform", choices = [ "rootonly", "intermediates", "fullchain", "all-except-root", "multifile", "pkcs12" ], default = "fullchain", help = "Specifies what to write into the output file. Possible options are %(choices)s. Default is %(default)s. When specifying multifile, a %%d format must be included in the filename to serve as a template; typical printf-style formatting can be used of course (e.g., %%02d).")
	parser.add_argument("--private-key", metavar = "filename", type = str, help = "When creating a PKCS#12 output file, this private key can also be included. By default, only the certificates are exported.")
	parser.add_argument("--pkcs12-legacy-crypto", action = "store_true", help = "Use crappy crypto to encrypt a PKCS#12 exported private key.")
	group = parser.add_mutually_exclusive_group()
	group.add_argument("--pkcs12-no-passphrase", action = "store_true", help = "Do not use any passphrase to protect the PKCS#12 private key.")
	group.add_argument("--pkcs12-passphrase-file", metavar = "filename", type = str, help = "Read the PKCS#12 passphrase from the first line of the given file. If omitted, by default a random passphrase will be generated and printed on stderr.")
	parser.add_argument("-o", "--outfile", metavar = "file", help = "Specifies the output filename. Defaults to stdout.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("crtfile", metavar = "crtfile", type = str, help = "Certificate that a chain shall be build for, in PEM format.")
mc.register("buildchain", "Build a certificate chain", genparser, action = ActionBuildChain, aliases = [ "bc" ])

def genparser(parser):
	parser.add_argument("-f", "--format", choices = [ "dot", "png", "ps", "pdf" ], default = None, help = "Specifies the output file format. Can be one of %(choices)s. When unspecified, the file extension out the output file is used to determine the file type.")
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
	group = parser.add_mutually_exclusive_group()
	group.add_argument("-g", "--gen-keyspec", metavar = "keyspec", type = __keyspec, help = "Private key specification to generate. Examples are rsa:1024 or ecc:secp256r1. Defaults to ecc:secp384r1.")
	group.add_argument("-w", "--hardware-key", metavar = "pkcs11uri", type = str, help = "Use a hardware token which stores the private key. The parameter gives the pkcs11 URI, e.g., 'pkcs11:object=mykey;type=private'")
	parser.add_argument("--pkcs11-so-search", metavar = "path", type = str, default = _default_so_search_path, help = "Gives the path that will be searched for the \"dynamic\" and \"module\" shared objects. The \"dynamic\" shared object is libpkcs11.so, the \"module\" shared object can be changed by the --pkcs11-module option. The search path defaults to %(default)s.")
	parser.add_argument("--pkcs11-module", metavar = "sofile", type = str, default = "opensc-pkcs11.so", help = "Name of the \"module\" shared object when using PKCS#11 keys. Defaults to %(default)s.")
	parser.add_argument("-p", "--parent-ca", metavar = "capath", type = str, help = "Parent CA directory. If omitted, CA certificate will be self-signed.")
	parser.add_argument("-s", "--subject-dn", metavar = "subject", type = str, default = "/CN=Root CA", help = "CA subject distinguished name. Defaults to %(default)s.")
	parser.add_argument("-d", "--validity-days", metavar = "days", type = int, default = 365, help = "Number of days that the newly created CA will be valid for. Defaults to %(default)s days.")
	parser.add_argument("-h", "--hashfnc", metavar = "alg", type = str, default = "sha384", help = "Hash function to use for signing the CA certificate. Defaults to %(default)s.")
	parser.add_argument("--serial", metavar = "serial", type = baseint, help = "Serial number to use for root CA certificate. Randomized by default.")
	parser.add_argument("--allow-duplicate-subjects", action = "store_true", help = "By default, subject distinguished names of all valid certificates below one CA must be unique. This option allows the CA to have duplicate distinguished names for certificate subjects.")
	parser.add_argument("--extension", metavar = "key=value", type = KeyValue, action = "append", default = [ ], help = "Additional certificate X.509 extension to include on top of the default CA extensions. Can be specified multiple times.")
	parser.add_argument("-f", "--force", action = "store_true", help = "By default, the capath will not be overwritten if it already exists. When this option is specified the complete directory will be erased before creating the new CA.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("capath", metavar = "capath", type = str, help = "Directory to create the new CA in.")
mc.register("createca", "Create a new certificate authority (CA)", genparser, aliases = [ "genca" ], action = ActionCreateCA)

def genparser(parser):
	parser.add_argument("-g", "--gen-keyspec", metavar = "keyspec", type = __keyspec, help = "Private key specification to generate for the certificate or CSR when it doesn't exist. Examples are rsa:1024 or ecc:secp256r1.")
	parser.add_argument("-k", "--keytype", choices = [ "pem", "der", "hw" ], default = "pem", help = "Private key type. Can be any of %(choices)s. Defaults to %(default)s.")
	parser.add_argument("-s", "--subject-dn", metavar = "subject", type = str, default = "/CN=New Cert", help = "Certificate/CSR subject distinguished name. Defaults to %(default)s.")
	parser.add_argument("-d", "--validity-days", metavar = "days", type = int, default = 365, help = "When creating a certificate, number of days that the certificate will be valid for. Defaults to %(default)s days.")
	parser.add_argument("-h", "--hashfnc", metavar = "alg", type = str, default = None, help = "Hash function to use for signing when creating a certificate. Defaults to the default hash function specified in the CA config.")
	parser.add_argument("-t", "--template", choices = [ "rootca", "ca", "tls-server", "tls-client" ], help = "Template to use for determining X.509 certificate extensions. Can be one of %(choices)s. By default, no extensions are included except for SAN.")
	parser.add_argument("--san-dns", metavar = "FQDN", type = str, action = "append", default = [ ], help = "Subject Alternative DNS name to include in the certificate or CSR. Can be specified multiple times.")
	parser.add_argument("--san-ip", metavar = "IP", type = str, action = "append", default = [ ], help = "Subject Alternative IP address to include in the certificate or CSR. Can be specified multiple times.")
	parser.add_argument("--extension", metavar = "key=value", type = KeyValue, action = "append", default = [ ], help = "Additional certificate X.509 extension to include on top of the extensions in the template and by the SAN parameters. Can be specified multiple times.")
	parser.add_argument("-f", "--force", action = "store_true", help = "Overwrite the output file if it already exists.")
	parser.add_argument("-c", "--create-crt", metavar = "capath", help = "Instead of creating a certificate signing request, directly create a certificate instead. Needs to supply the CA path that should issue the certificate.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("key_filename", metavar = "in_key_filename", type = str, help = "Filename of the input private key or PKCS#11 URI (as specified in RFC7512 in case of a hardware key type.")
	parser.add_argument("out_filename", metavar = "out_filename", type = str, help = "Filename of the output certificate signing request or certificate.")
mc.register("createcsr", "Create a new certificate signing request (CSR) or certificate", genparser, aliases = [ "gencsr", "createcrt", "gencrt" ], action = ActionCreateCSR)

def genparser(parser):
	parser.add_argument("-s", "--subject-dn", metavar = "subject", type = str, help = "Certificate's subject distinguished name. Defaults to the subject given in the CSR.")
	parser.add_argument("-d", "--validity-days", metavar = "days", type = int, default = 365, help = "Number of days that the newly created certificate will be valid for. Defaults to %(default)s days.")
	parser.add_argument("-h", "--hashfnc", metavar = "alg", type = str, default = None, help = "Hash function to use for signing. Defaults to the default hash function specified in the CA config.")
	parser.add_argument("-t", "--template", choices = [ "rootca", "ca", "tls-server", "tls-client" ], help = "Template to use for determining X.509 certificate extensions. Can be one of %(choices)s. By default, no extensions are included except for SAN.")
	parser.add_argument("--san-dns", metavar = "FQDN", type = str, action = "append", default = [ ], help = "Subject Alternative DNS name to include in the certificate. Can be specified multiple times.")
	parser.add_argument("--san-ip", metavar = "IP", type = str, action = "append", default = [ ], help = "Subject Alternative IP address to include in the CRT. Can be specified multiple times.")
	parser.add_argument("--extension", metavar = "key=value", type = KeyValue, action = "append", default = [ ], help = "Additional certificate X.509 extension to include on top of the extensions in the template and by the SAN parameters. Can be specified multiple times.")
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
	parser.add_argument("-d", "--validity-days", metavar = "days", type = int, default = 30, help = "Number of days until the CRLs 'nextUpdate' field will expire. Defaults to %(default)s days.")
	parser.add_argument("-h", "--hashfnc", metavar = "alg", type = str, default = "sha256", help = "Hash function to use for signing the CRL. Defaults to %(default)s.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("capath", metavar = "capath", type = str, help = "CA which should generate the CRL.")
	parser.add_argument("crl_filename", metavar = "crl_filename", type = str, help = "Filename of the output CRL.")
mc.register("createcrl", "Generate a certificate revocation list (CRL)", genparser, action = ActionCreateCRL, aliases = [ "gencrl" ])

def genparser(parser):
	parser.add_argument("-d", "--prime-db", metavar = "path", type = str, default = ".", help = "Prime database directory. Defaults to %(default)s and searches for files called primes_{bitlen}.txt in this directory.")
	parser.add_argument("-b", "--bitlen", metavar = "bits", type = int, default = 2048, help = "Bitlength of modulus. Defaults to %(default)d bits.")
	parser.add_argument("-e", "--public-exponent", metavar = "exp", type = baseint, default = 0x10001, help = "Public exponent e (or d in case --switch-e-d is specified) to use. Defaults to 0x%(default)x. Will be randomly chosen from 2..n-1 if set to -1.")
	parser.add_argument("--switch-e-d", action = "store_true", help = "Switch e with d when generating keypair.")
	parser.add_argument("--accept-unusable-key", action = "store_true", help = "Disregard integral checks, such as if gcd(e, phi(n)) == 1 before inverting e. Might lead to an unusable key or might fail altogether.")
	parser.add_argument("--close-q", action = "store_true", help = "Use a value for q that is very close to the value of p so that search starting from sqrt(n) is computationally feasible to factor the modulus. Note that for this, the bitlength of the modulus must be evenly divisible by two.")
	parser.add_argument("--q-stepping", metavar = "int", type = baseint, default = 1, help = "When creating a close-q RSA keypair, q is chosen by taking p and incrementing it repeatedly by a random int from 2 to (2 * q-stepping). The larger q-stepping is therefore chosen, the further apart p and q will be. By default, q-stepping is the minimum value of %(default)d.")
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
	parser.add_argument("-n", "--server-name", metavar = "fqdn", type = str, help = "Check if the certificate is valid for the given hostname.")
	parser.add_argument("--fast-rsa", action = "store_true", help = "Skip some time-intensive number theoretical tests for RSA moduli in order to speed up checking. Less thorough, but much faster.")
	parser.add_argument("--include-raw-data", action = "store_true", help = "Add the raw data such as base64-encoded certificate and signatures into the result as well.")
	parser.add_argument("--print-raw", action = "store_true", help = "Instead of printing the human-readable version of the analysis, print the raw JSON data.")
	parser.add_argument("-w", "--write-json", metavar = "filename", type = str, help = "Write a JSON output document with detailed information about the checked certificate in the filename.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("crt_filenames", metavar = "crt_filename", type = str, nargs = "+", help = "Filename of the input certificate or certificates in PEM format.")
mc.register("examinecert", "Examine an X.509 certificate", genparser, action = ActionExamineCert, aliases = [ "analyze" ], visible = False)

def genparser(parser):
	parser.add_argument("--key_template", metavar = "path", default = "forged_%02d.key", help = "Output template for key files. Should contain '%%d' to indicate element in chain. Defaults to '%(default)s'.")
	parser.add_argument("--cert_template", metavar = "path", default = "forged_%02d.crt", help = "Output template for certificate files. Should contain '%%d' to indicate element in chain. Defaults to '%(default)s'.")
	parser.add_argument("-r", "--recalculate-keyids", action = "store_true", help = "By default, Subject Key Identifier and Authority Key Identifier X.509 extensions are kept as-is in the forged certificates. Specifying this will recalculate the IDs to fit the forged keys.")
	parser.add_argument("-f", "--force", action = "store_true", help = "Overwrite key/certificate files.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("crt_filename", metavar = "crt_filename", type = str, help = "Filename of the input certificate or certificates PEM format.")
mc.register("forgecert", "Forge an X.509 certificate", genparser, action = ActionForgeCert)

def genparser(parser):
	parser.add_argument("--no-pem", action = "store_true", help = "Do not search for any PEM encoded blobs.")
	parser.add_argument("--no-der", action = "store_true", help = "Do not search for any DER encoded blobs.")
	parser.add_argument("-i", "--include-dertype", metavar = "class", action = "append", default = [ ], help = "Include the specified DER handler class in the search. Defaults to all known classes if omitted. Can be specified multiple times and must be one of %s." % (", ".join(sorted(ActionScrape.handler_classes))))
	parser.add_argument("-e", "--exclude-dertype", metavar = "class", action = "append", default = [ ], help = "Exclude the specified DER handler class in the search. Can be specified multiple times and must be one of %s." % (", ".join(sorted(ActionScrape.handler_classes))))
	parser.add_argument("--extract-nested", action = "store_true", help = "By default, fully overlapping blobs will not be extracted. For example, every X.509 certificate also contains a public key inside that would otherwise be found as well. When this option is given, any blobs are extracted regardless if they're fully contained in another blob or not.")
	parser.add_argument("--keep-original-der", action = "store_true", help = "When finding DER blobs, do not convert them to PEM format, but leave them as-is.")
	parser.add_argument("--allow-non-unique-blobs", action = "store_true", help = "For all matches, the SHA256 hash is used to determine if the data is unique and findings are by default only written to disk once. With this option, blobs that very likely are duplicates are written to disk for every ocurrence.")
	parser.add_argument("--disable-der-sanity-checks", action = "store_true", help = "For DER serialization, not only is it checked that deserialization is possible, but additional checks are performed for some data types to ensure a low false-positive rate. For example, DSA signatures with short r/s pairs are discarded by default or implausible version numbers for EC keys. With this option, these sanity checks will be disabled and therefore structurally correct (but implausible) false-positives are also written.")
	parser.add_argument("--outmask", metavar = "mask", default = "scrape_%(offset)07x_%(type)s.%(ext)s", help = "Filename mask that's used for output. Defaults to %(default)s and can use printf-style substitutions offset, type and ext.")
	parser.add_argument("-w", "--write-json", metavar = "filename", type = str, help = "Write the stats with detailed information about matches into the given filename.")
	parser.add_argument("-o", "--outdir", metavar = "path", type = str, default = "scrape", help = "Output directory. Defaults to %(default)s.")
	parser.add_argument("-f", "--force", action = "store_true", help = "Overwrite key/certificate files and proceed even if outdir already exists.")
	parser.add_argument("-s", "--seek-offset", metavar = "offset", type = baseint_unit, default = "0", help = "Offset to seek into file. Supports hex/octal/binary prefixes and SI/binary SI (k, ki, M, Mi, etc.) suffixes. Defaults to %(default)s.")
	parser.add_argument("-l", "--analysis-length", metavar = "length", type = baseint_unit, default = None, help = "Amount of data to inspect at max. Supports hex/octal/binary prefixes and SI/binary SI (k, ki, M, Mi, etc.) suffixes. Defaults to everything until EOF is hit.")
	parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity level. Can be specified multiple times.")
	parser.add_argument("filename", metavar = "filename", type = str, help = "File that should be scraped for certificates or keys.")
mc.register("scrape", "Scrape input file for certificates, keys or signatures", genparser, action = ActionScrape)

try:
	mc.run(sys.argv[1:])
except (UserErrorException, InvisibleUserErrorException) as e:
	if logging.root.level == logging.DEBUG:
		traceback.print_exc()
		print(file = sys.stderr)
	if isinstance(e, UserErrorException) or (logging.root.level == logging.DEBUG):
		print("%s: %s" % (e.__class__.__name__, str(e)), file = sys.stderr)
	elif isinstance(e, CmdExecutionFailedException):
		if len(e.stderr) > 0:
			print("Subprocess command execution failed:", file = sys.stderr)
			sys.stderr.write(e.stderr.decode())
		else:
			print("Subprocess command execution failed.")
	else:
		print("Failure while processing this request: %s" % (e.__class__.__name__), file = sys.stderr)
	sys.exit(1)
