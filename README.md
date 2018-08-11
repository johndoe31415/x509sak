# x509sak
[![Build Status](https://travis-ci.org/johndoe31415/x509sak.svg?branch=master)](https://travis-ci.org/johndoe31415/x509sak)

X.509 Swiss Army Knife (x509sak) is a toolkit written in Python that acts as a
boilerplate on top of OpenSSL to ease creation of X.509 certificates,
certificate signing requests and CAs. It can automatically find CA chains and
output them in a specifically desired format, graph CA hierarchies and more.

The tool is used similarly to OpenSSL in its syntax. The help page is meant to
be comprehensive and self-explanatory. These are the currently available commands:

[//]: # (Begin of summary -- auto-generated, do not edit!)
```
$ ./x509sak.py
Error: No command supplied.
Syntax: ./x509sak.py [command] [options]

Available commands:

Options vary from command to command. To receive further info, type
    ./x509sak.py [command] --help
    buildchain         Build a certificate chain
    graph              Graph a certificate pool
    findcrt            Find a specific certificate
    createca           Create a new certificate authority (CA)
    createcsr          Create a new certificate signing request (CSR) or
                       certificate
    signcsr            Make a certificate authority (CA) sign a crtificate
                       signing request (CSR) and output the certificate
    revokecrt          Revoke a specific certificate
    createcrl          Generate a certificate revocation list (CRL)
    genbrokenrsa       Generate broken RSA keys for use in pentetration testing
    dumpkey            Dump a key in text form
    forgecert          Forge an X.509 certificate
    scrape             Scrape input file for certificates, keys or signatures
```
[//]: # (End of summary -- auto-generated, do not edit!)

## Dependencies
x509sak requires Python3, pyasn1 and pyasn1_modules support. It also relies on
OpenSSL. If you want graph support, then you also need to install the Graphviz
package as well. Note that pyasn1_modules inside the Ubuntu tree (up until
3'2018, Ubuntu Artful MATE, v0.0.7-0.1) is broken and you'll need to use a
newer version (0.2.1 works). In later Ubuntu versions (Bionic) this is already
included by default:

```
# apt-get install openssl python3-pyasn1 python3-pyasn1-modules graphviz
```

If you want to run all the tests, you should also have SoftHSM2, OpenSC and the
PKCS#11 OpenSSL engine driver installed to be able to do PKCS#11 testing:

```
# apt-get install opensc softhsm2 libengine-pkcs11-openssl
```


## Using x509sak with hardware tokens
x509sak works nicely with hardware tokens such as the NitroKey HSM. It does not
allow key generation for these devices, but can use the pre-generated keys for
CA management. For example, let's say you used a [tool like
nitrotool](https://github.com/johndoe31415/nitrotool) to generate an ECC
keypair that is called "my_secure_key". You now want a CA that's based off that
key.  Quite an easy task:

```
$ ./x509sak.py createca -w "pkcs11:object=my_secure_key;type=private" -s "/CN=My Secure CA" my_secure_ca
Enter PKCS#11 token PIN for UserPIN (SmartCard-HSM): 123456
```

You enter your Pin, hit return and it's done! The CA has been created:

```
$ openssl x509 -in my_secure_ca/CA.crt -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            c3:86:c2:43:4b:2d:62:12
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = My Secure CA
        Validity
            Not Before: Jul 14 10:47:49 2018 GMT
            Not After : Jul 14 10:47:49 2019 GMT
        Subject: CN = My Secure CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:8a:8f:c7:99:3b:b1:cf:63:5f:c7:c8:87:50:80:
                    26:4d:22:96:9f:2f:67:f8:ea:f6:f2:1b:96:e4:e2:
                    4b:af:15:fe:79:77:52:50:d1:f6:a3:20:7b:ca:ce:
                    5e:bc:25:5e:30:2d:1a:71:cb:8f:ff:79:46:4f:ec:
                    58:04:e1:f7:f0
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                9B:4E:14:4E:0D:C5:23:D9:06:06:06:7D:39:8F:3C:88:1D:66:35:55
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:79:a2:91:1e:ca:2d:18:5b:26:59:14:b1:f1:0c:
         2f:0f:41:d8:ab:bc:02:2f:e9:c2:dc:97:c1:19:67:9e:c7:8d:
         02:21:00:ef:73:02:6a:a4:ad:e8:f0:ef:49:02:cf:34:08:b7:
         2e:fa:82:16:47:8c:44:7f:bb:ad:f0:c0:be:7a:e6:e1:81
```

It's similarly easy to create certificates off this hardware-backed CA:

```
$ ./x509sak.py createcsr -s "/CN=Software Key Client" -t tls-client -c my_secure_ca client.key client.crt
Enter PKCS#11 token PIN for UserPIN (SmartCard-HSM):
```

Again, with one command you've created the client certificate:

```
$ openssl x509 -in client.crt -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = My Secure CA
        Validity
            Not Before: Jul 14 10:50:19 2018 GMT
            Not After : Jul 14 10:50:19 2019 GMT
        Subject: CN = Software Key Client
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:5a:68:1b:f2:ea:29:71:23:39:66:bd:b7:6a:9c:
                    0c:69:8d:a9:e8:7f:93:a8:32:21:d7:f2:93:e8:52:
                    c5:83:65:7b:13:62:04:9f:64:c6:54:fd:24:8a:64:
                    d2:49:cd:8d:27:61:b3:41:44:d3:89:51:39:78:29:
                    b2:ff:1a:3a:b6:e0:74:c6:15:92:26:f9:42:2b:0d:
                    04:74:1b:3d:13:f8:78:53:a5:be:6f:13:04:01:05:
                    f7:40:4b:6a:89:4c:54
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                keyid:9B:4E:14:4E:0D:C5:23:D9:06:06:06:7D:39:8F:3C:88:1D:66:35:55

            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Key Agreement
            Netscape Cert Type: 
                SSL Client
            X509v3 Subject Key Identifier: 
                0C:1F:31:4C:BA:E2:C6:33:65:9D:ED:DA:FC:16:29:27:E0:95:AF:E2
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:3f:84:40:bb:50:2e:7c:8c:3b:2f:51:80:f9:20:
         a7:bb:7d:17:58:c6:44:70:20:eb:74:46:5a:ae:95:4e:9e:81:
         02:20:0c:98:35:63:8d:2f:1b:ad:32:d4:06:2f:c8:e7:2c:8a:
         79:b7:5a:e0:21:51:63:0b:39:82:9f:ff:8d:ee:c3:e2
```

For simplicity, you can specify either a full pkcs11-URI according to RFC7512
or you can use certain abbreviations that make it easier. All of the following
work for a key that's named 'my key' and that has ID 0xabcd:

```
pkcs11:object=my%20key;type=private
pkcs11:id=%ab%cd;type=private
label=my key
id=0xabcd
id=43981
```

The latter variants (label=..., id=...) will automatically be converted to
pkcs11 URIs internally.

## buildchain
The "buildchain" command is useful if you want to have a complete (or partial)
certificate chain from a given leaf certfificate and a bundle of CAs. x509sak
will figure out which of the CAs are appropriate (if any) and generate a chain
in the order you want (root to leaf or leaf to root) including the certs you
want (e.g., all certificates, all except root cert, etc.). This is useful if
you have, for example, a webserver certificate and want to automatically find
the chain of trust that you can use to deploy on your webserver.

[//]: # (Begin of cmd-buildchain -- auto-generated, do not edit!)
```
usage: ./x509sak.py buildchain [-s path] [--inform {pem,der}]
                               [--order-leaf-to-root] [--allow-partial-chain]
                               [--dont-trust-crtfile]
                               [--outform {rootonly,intermediates,fullchain,all-except-root,multifile,pkcs12}]
                               [--private-key filename]
                               [--pkcs12-legacy-crypto]
                               [--pkcs12-no-passphrase | --pkcs12-passphrase-file filename]
                               [-o file] [-v] [--help]
                               crtfile

Build a certificate chain

positional arguments:
  crtfile               Certificate that a chain shall be build for, in PEM
                        format.

optional arguments:
  -s path, --ca-source path
                        CA file (PEM format) or directory (containing
                        .pem/.crt files) to include when building the chain.
                        Can be specified multiple times to include multiple
                        locations.
  --inform {pem,der}    Specifies input file format for certificate. Possible
                        options are pem, der. Default is pem.
  --order-leaf-to-root  By default, certificates are ordered with the root CA
                        first and intermediate certificates following up to
                        the leaf. When this option is specified, the order is
                        inverted and go from leaf certificate to root.
  --allow-partial-chain
                        When building the certificate chain, a full chain must
                        be found or the chain building fails. When this option
                        is specified, also partial chain matches are
                        permitted, i.e., not going up to a root CA. Note that
                        this can have undesired side effects when no root
                        certificates are found at all (the partial chain will
                        then consist of only the leaf certificate itself).
  --dont-trust-crtfile  When there's multiple certificates in the given
                        crtfile in PEM format, they're by default all added to
                        the truststore. With this option, only the leaf cert
                        is taken from the crtfile and they're not added to the
                        trusted pool.
  --outform {rootonly,intermediates,fullchain,all-except-root,multifile,pkcs12}
                        Specifies what to write into the output file. Possible
                        options are rootonly, intermediates, fullchain, all-
                        except-root, multifile, pkcs12. Default is fullchain.
                        When specifying multifile, a %d format must be
                        included in the filename to serve as a template;
                        typical printf-style formatting can be used of course
                        (e.g., %02d).
  --private-key filename
                        When creating a PKCS#12 output file, this private key
                        can also be included. By default, only the
                        certificates are exported.
  --pkcs12-legacy-crypto
                        Use crappy crypto to encrypt a PKCS#12 exported
                        private key.
  --pkcs12-no-passphrase
                        Do not use any passphrase to protect the PKCS#12
                        private key.
  --pkcs12-passphrase-file filename
                        Read the PKCS#12 passphrase from the first line of the
                        given file. If omitted, by default a random passphrase
                        will be generated and printed on stderr.
  -o file, --outfile file
                        Specifies the output filename. Defaults to stdout.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-buildchain -- auto-generated, do not edit!)

## graph
The graph utility can be used to plot multiple certificates and their
certificate hierarchy. Some metadata is displayed within the graph as well.
Here's an example of some certificates that I've plotted:

![Certificate Graph](https://raw.githubusercontent.com/johndoe31415/x509sak/master/docs/test_graph.png)

[//]: # (Begin of cmd-graph -- auto-generated, do not edit!)
```
usage: ./x509sak.py graph [-f {dot,png,ps,pdf}] -o file [-v] [--help]
                          crtsource [crtsource ...]

Graph a certificate pool

positional arguments:
  crtsource             Certificate file (in PEM format) or directory
                        (conainting PEM-formatted .pem or .crt files) which
                        should be included in the graph.

optional arguments:
  -f {dot,png,ps,pdf}, --format {dot,png,ps,pdf}
                        Specifies the output file format. Can be one of dot,
                        png, ps, pdf, defaults to None. When unspecified, the
                        file extension out the output file is used to
                        determine the file type.
  -o file, --outfile file
                        Specifies the output filename. Mandatory argument.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-graph -- auto-generated, do not edit!)

## findcrt
When looking for a bunch of certificates (some of which might be in PEM format)
by their authoritative hash (i.e., the SHA256 hash over their
DER-representation), findcrt can help you out. You specify a bunch of
certificates and the hash prefix you're looking for and x509sak will show it to
you.

[//]: # (Begin of cmd-findcrt -- auto-generated, do not edit!)
```
usage: ./x509sak.py findcrt [-h hash] [-v] [--help] crtsource [crtsource ...]

Find a specific certificate

positional arguments:
  crtsource             Certificate file (in PEM format) or directory
                        (conainting PEM-formatted .pem or .crt files) which
                        should be included in the search.

optional arguments:
  -h hash, --hashval hash
                        Find only certificates with a particular hash prefix.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-findcrt -- auto-generated, do not edit!)

## createca
Creating a CA structure that can be used with "openssl ca" is tedious. The
"createca" command does exactly this for you in one simple command. The created
OpenSSL config file directly works with "openssl ca" for manual operation but
can also be used with other x509sak commands (e.g., creating or revoking
certificates). x509sak takes care that you have all the necessary setup files
in place (index, serial, etc.) and can just as easily create intermediate CAs
as it can create root CAs.

[//]: # (Begin of cmd-createca -- auto-generated, do not edit!)
```
usage: ./x509sak.py createca [-g keyspec | -w pkcs11uri]
                             [--pkcs11-so-search path]
                             [--pkcs11-module sofile] [-p capath] [-s subject]
                             [-d days] [-h alg] [--serial serial]
                             [--allow-duplicate-subjects]
                             [--extension key=value] [-f] [-v] [--help]
                             capath

Create a new certificate authority (CA)

positional arguments:
  capath                Directory to create the new CA in.

optional arguments:
  -g keyspec, --gen-keyspec keyspec
                        Private key specification to generate. Examples are
                        rsa:1024 or ecc:secp256r1. Defaults to ecc:secp384r1.
  -w pkcs11uri, --hardware-key pkcs11uri
                        Use a hardware token which stores the private key. The
                        parameter gives the pkcs11 URI, e.g.,
                        'pkcs11:object=mykey;type=private'
  --pkcs11-so-search path
                        Gives the path that will be searched for the "dynamic"
                        and "module" shared objects. The "dynamic" shared
                        object is libpkcs11.so, the "module" shared object can
                        be changed by the --pkcs11-module option. The search
                        path defaults to
                        /usr/local/lib:/usr/lib:/usr/lib/x86_64-linux-
                        gnu:/usr/lib/x86_64-linux-
                        gnu/openssl-1.0.2/engines:/usr/lib/x86_64-linux-
                        gnu/engines-1.1.
  --pkcs11-module sofile
                        Name of the "module" shared object when using PKCS#11
                        keys. Defaults to opensc-pkcs11.so.
  -p capath, --parent-ca capath
                        Parent CA directory. If omitted, CA certificate will
                        be self-signed.
  -s subject, --subject-dn subject
                        CA subject distinguished name. Defaults to /CN=Root
                        CA.
  -d days, --validity-days days
                        Number of days that the newly created CA will be valid
                        for. Defaults to 365 days.
  -h alg, --hashfnc alg
                        Hash function to use for signing the CA certificate.
                        Defaults to sha384.
  --serial serial       Serial number to use for root CA certificate.
                        Randomized by default.
  --allow-duplicate-subjects
                        By default, subject distinguished names of all valid
                        certificates below one CA must be unique. This option
                        allows the CA to have duplicate distinguished names
                        for certificate subjects.
  --extension key=value
                        Additional certificate X.509 extension to include on
                        top of the default CA extensions. Can be specified
                        multiple times.
  -f, --force           By default, the capath will not be overwritten if it
                        already exists. When this option is specified the
                        complete directory will be erased before creating the
                        new CA.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-createca -- auto-generated, do not edit!)

## createcsr
The "createcsr" command can (as the name suggests) create CSRs, but also can
directly generate CRTs that are signed by a previously created CA. The
advantage over using OpenSSL manually is that the API is quite simple to
configure the certificate manually for most cases (e.g., webserver certificates
with X.509 Subject Alternative Name set), but also is flexible enough for
custom stuff by including your custom extensions directly into the extension
file configuration used by OpenSSL.

[//]: # (Begin of cmd-createcsr -- auto-generated, do not edit!)
```
usage: ./x509sak.py createcsr [-g keyspec] [-k {pem,der,hw}] [-s subject]
                              [-d days] [-h alg]
                              [-t {rootca,ca,tls-server,tls-client}]
                              [--san-dns FQDN] [--san-ip IP]
                              [--extension key=value] [-f] [-c capath] [-v]
                              [--help]
                              in_key_filename out_filename

Create a new certificate signing request (CSR) or certificate

positional arguments:
  in_key_filename       Filename of the input private key or PKCS#11 URI (as
                        specified in RFC7512 in case of a hardware key type.
  out_filename          Filename of the output certificate signing request or
                        certificate.

optional arguments:
  -g keyspec, --gen-keyspec keyspec
                        Private key specification to generate for the
                        certificate or CSR when it doesn't exist. Examples are
                        rsa:1024 or ecc:secp256r1.
  -k {pem,der,hw}, --keytype {pem,der,hw}
                        Private key type. Can be any of pem, der, hw. Defaults
                        to pem.
  -s subject, --subject-dn subject
                        Certificate/CSR subject distinguished name. Defaults
                        to /CN=New Cert.
  -d days, --validity-days days
                        When creating a certificate, number of days that the
                        certificate will be valid for. Defaults to 365 days.
  -h alg, --hashfnc alg
                        Hash function to use for signing when creating a
                        certificate. Defaults to the default hash function
                        specified in the CA config.
  -t {rootca,ca,tls-server,tls-client}, --template {rootca,ca,tls-server,tls-client}
                        Template to use for determining X.509 certificate
                        extensions. Can be one of rootca, ca, tls-server, tls-
                        client. By default, no extensions are included except
                        for SAN.
  --san-dns FQDN        Subject Alternative DNS name to include in the
                        certificate or CSR. Can be specified multiple times.
  --san-ip IP           Subject Alternative IP address to include in the
                        certificate or CSR. Can be specified multiple times.
  --extension key=value
                        Additional certificate X.509 extension to include on
                        top of the extensions in the template and by the SAN
                        parameters. Can be specified multiple times.
  -f, --force           Overwrite the output file if it already exists.
  -c capath, --create-crt capath
                        Instead of creating a certificate signing request,
                        directly create a certificate instead. Needs to supply
                        the CA path that should issue the certificate.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-createcsr -- auto-generated, do not edit!)

## signcsr
The signcsr command allows you to turn a CSR into a certificate by signing it
by a CA private key.

[//]: # (Begin of cmd-signcsr -- auto-generated, do not edit!)
```
usage: ./x509sak.py signcsr [-s subject] [-d days] [-h alg]
                            [-t {rootca,ca,tls-server,tls-client}]
                            [--san-dns FQDN] [--san-ip IP]
                            [--extension key=value] [-f] [-v] [--help]
                            capath in_csr_filename out_crt_filename

Make a certificate authority (CA) sign a crtificate signing request (CSR) and
output the certificate

positional arguments:
  capath                Directory of the signing CA.
  in_csr_filename       Filename of the input certificate signing request.
  out_crt_filename      Filename of the output certificate.

optional arguments:
  -s subject, --subject-dn subject
                        Certificate's subject distinguished name. Defaults to
                        the subject given in the CSR.
  -d days, --validity-days days
                        Number of days that the newly created certificate will
                        be valid for. Defaults to 365 days.
  -h alg, --hashfnc alg
                        Hash function to use for signing. Defaults to the
                        default hash function specified in the CA config.
  -t {rootca,ca,tls-server,tls-client}, --template {rootca,ca,tls-server,tls-client}
                        Template to use for determining X.509 certificate
                        extensions. Can be one of rootca, ca, tls-server, tls-
                        client. By default, no extensions are included except
                        for SAN.
  --san-dns FQDN        Subject Alternative DNS name to include in the
                        certificate. Can be specified multiple times.
  --san-ip IP           Subject Alternative IP address to include in the CRT.
                        Can be specified multiple times.
  --extension key=value
                        Additional certificate X.509 extension to include on
                        top of the extensions in the template and by the SAN
                        parameters. Can be specified multiple times.
  -f, --force           Overwrite the output certificate file if it already
                        exists.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-signcsr -- auto-generated, do not edit!)

## revokecrt
With revokecrt it's possible to easily revoke a certificate that you've
previous generated. Simply specify the CA and the certificate that you want to
revoke and you're set.

[//]: # (Begin of cmd-revokecrt -- auto-generated, do not edit!)
```
usage: ./x509sak.py revokecrt [-v] [--help] capath crt_filename

Revoke a specific certificate

positional arguments:
  capath         CA which created the certificate.
  crt_filename   Filename of the output certificate.

optional arguments:
  -v, --verbose  Increase verbosity level. Can be specified multiple times.
  --help         Show this help page.
```
[//]: # (End of cmd-revokecrt -- auto-generated, do not edit!)

## createcrl
The createcrl command does what it suggests: It creates a CRL for a given CA
that is valid for a specified duration and that's signed with a given hash
function.

[//]: # (Begin of cmd-createcrl -- auto-generated, do not edit!)
```
usage: ./x509sak.py createcrl [-d days] [-h alg] [-v] [--help]
                              capath crt_filename

Generate a certificate revocation list (CRL)

positional arguments:
  capath                CA which should generate the CRL.
  crt_filename          Filename of the output CRL.

optional arguments:
  -d days, --validity-days days
                        Number of days until the CRLs 'nextUpdate' field will
                        expire. Defaults to 30 days.
  -h alg, --hashfnc alg
                        Hash function to use for signing the CRL. Defaults to
                        sha256.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-createcrl -- auto-generated, do not edit!)

## genbrokenrsa
With genbrokenrsa it is possible to generate deliberately malformed or odd RSA
keys. For example, RSA keys with a custom value for the public exponent e, or
RSA keys which have a very small exponent d (e.g, 3) and a correspondingly
large exponent e. Note that keys generated by this tool are *exclusively for
testing purposes* and may not, under any circumstances, be used for actual
cryptographic applications. They are *not secure*.

[//]: # (Begin of cmd-genbrokenrsa -- auto-generated, do not edit!)
```
usage: ./x509sak.py genbrokenrsa [-d path] [-b bits] [-e exp] [--switch-e-d]
                                 [--accept-unusable-key] [--close-q] [-o file]
                                 [-f] [-v] [--help]

Generate broken RSA keys for use in pentetration testing

optional arguments:
  -d path, --prime-db path
                        Prime database directory. Defaults to . and searches
                        for files called primes_{bitlen}.txt in this
                        directory.
  -b bits, --bitlen bits
                        Bitlength of primes p/q to choose. Note that the
                        modulus bitlength will be twice of that because it is
                        the product of two primes (n = pq). Defaults to 2048
                        bits.
  -e exp, --public-exponent exp
                        Public exponent e (or d in case --switch-e-d is
                        specified) to use. Defaults to 0x10001. Will be
                        randomly chosen from 2..n-1 if set to -1.
  --switch-e-d          Swtich e with d when generating keypair.
  --accept-unusable-key
                        Disregard integral checks, such as if gcd(e, phi(n))
                        == 1 before inverting e. Might lead to an unusable key
                        or might fail altogether.
  --close-q             Use a value for q that is very close to the value of p
                        so that search starting from sqrt(n) is
                        computationally feasible to factor the modulus.
  -o file, --outfile file
                        Output filename. Defaults to broken_rsa.key.
  -f, --force           Overwrite output file if it already exists instead of
                        bailing out.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-genbrokenrsa -- auto-generated, do not edit!)

## dumpkey
The dumpkey facility can be used to dump the public/private key parameters of a
given PEM keyfile into Python-code for further processing.

[//]: # (Begin of cmd-dumpkey -- auto-generated, do not edit!)
```
usage: ./x509sak.py dumpkey [-t {rsa,ecc}] [-p] [-v] [--help] key_filename

Dump a key in text form

positional arguments:
  key_filename          Filename of the input key file in PEM format.

optional arguments:
  -t {rsa,ecc}, --key-type {rsa,ecc}
                        Type of private key to import. Can be one of rsa, ecc,
                        defaults to rsa. Disregarded for public keys and
                        determined automatically.
  -p, --public-key      Input is a public key, not a private key.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-dumpkey -- auto-generated, do not edit!)

## forgecert
With the forgecert tool you can forge a certificate chain. The input PEM file
must begin with a self-signed root certificate and each following certificate
must descend from its predecessor. The functionality is rather simplistic
currently. The purpose is to create certificates which look and feel like their
"original" counterparts, but are obviously fakes. This is for white hat testing
of implementations.

[//]: # (Begin of cmd-forgecert -- auto-generated, do not edit!)
```
usage: ./x509sak.py forgecert [--key_template path] [--cert_template path]
                              [-r] [-f] [-v] [--help]
                              crt_filename

Forge an X.509 certificate

positional arguments:
  crt_filename          Filename of the input certificate or certificates PEM
                        format.

optional arguments:
  --key_template path   Output template for key files. Should contain '%d' to
                        indicate element in chain. Defaults to
                        'forged_%02d.key'.
  --cert_template path  Output template for certificate files. Should contain
                        '%d' to indicate element in chain. Defaults to
                        'forged_%02d.crt'.
  -r, --recalculate-keyids
                        By default, Subject Key Identifier and Authority Key
                        Identifier X.509 extensions are kept as-is in the
                        forged certificates. Specifying this will recalculate
                        the IDs to fit the forged keys.
  -f, --force           Overwrite key/certificate files.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-forgecert -- auto-generated, do not edit!)

## scrape
With the scrape tool you can analyze binary blobs or whole disks and search
them for PEM or DER-encoded blobs. This is interesting if, for example, you're
doing firmware analysis. DER analysis is quite slow because for every potential
sequence beginning (0x30), decoding of all supported schema is attempted. It
can be sped up if you're only looking for a particular data type instead of all
of them. In contrast, scanning for PEM data is much faster because PEM markers
have a much smaller false positive rate. For every occurrence that is found
inside the analyzed file, the contents are written to a own file in the output
directory.

[//]: # (Begin of cmd-scrape -- auto-generated, do not edit!)
```
usage: ./x509sak.py scrape [--no-pem] [--no-der] [-i class] [-e class]
                           [--extract-nested] [--keep-original-der]
                           [--allow-non-unique-blobs]
                           [--disable-der-sanity-checks] [--outmask mask]
                           [-w filename] [-o path] [-f] [-s offset]
                           [-l length] [-v] [--help]
                           filename

Scrape input file for certificates, keys or signatures

positional arguments:
  filename              File that should be scraped for certificates or keys.

optional arguments:
  --no-pem              Do not search for any PEM encoded blobs.
  --no-der              Do not search for any DER encoded blobs.
  -i class, --include-dertype class
                        Include the specified DER handler class in the search.
                        Defaults to all known classes if omitted. Can be
                        specified multiple times and must be one of crt,
                        dsa_key, dsa_sig, ec_key, pkcs12, pubkey, rsa_key.
  -e class, --exclude-dertype class
                        Exclude the specified DER handler class in the search.
                        Can be specified multiple times and must be one of
                        crt, dsa_key, dsa_sig, ec_key, pkcs12, pubkey,
                        rsa_key.
  --extract-nested      By default, fully overlapping blobs will not be
                        extracted. For example, every X.509 certificate also
                        contains a public key inside that would otherwise be
                        found as well. When this option is given, any blobs
                        are extracted regardless if they're fully contained in
                        another blob or not.
  --keep-original-der   When finding DER blobs, do not convert them to PEM
                        format, but leave them as-is.
  --allow-non-unique-blobs
                        For all matches, the SHA256 hash is used to determine
                        if the data is unique and findings are by default only
                        written to disk once. With this option, blobs that
                        very likely are duplicates are written to disk for
                        every ocurrence.
  --disable-der-sanity-checks
                        For DER serialization, not only is it checked that
                        deserialization is possible, but additional checks are
                        performed for some data types to ensure a low false-
                        positive rate. For example, DSA signatures with short
                        r/s pairs are discarded by default or implausible
                        version numbers for EC keys. With this option, these
                        sanity checks will be disabled and therefore
                        structurally correct (but implausible) false-positives
                        are also written.
  --outmask mask        Filename mask that's used for output. Defaults to
                        scrape_%(offset)07x_%(type)s.%(ext)s and can use
                        printf-style substitutions offset, type and ext.
  -w filename, --write-json filename
                        Write the stats with detailed information about
                        matches into the given filename.
  -o path, --outdir path
                        Output directory. Defaults to scrape.
  -f, --force           Overwrite key/certificate files and proceed even if
                        outdir already exists.
  -s offset, --seek-offset offset
                        Offset to seek into file. Supports hex/octal/binary
                        prefixes and SI/binary SI (k, ki, M, Mi, etc.)
                        suffixes. Defaults to 0.
  -l length, --analysis-length length
                        Amount of data to inspect at max. Supports
                        hex/octal/binary prefixes and SI/binary SI (k, ki, M,
                        Mi, etc.) suffixes. Defaults to everything until EOF
                        is hit.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-scrape -- auto-generated, do not edit!)

# License
GNU GPL-3.
