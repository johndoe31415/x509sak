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
    genbrokenrsa       Generate broken RSA keys for use in pentetration testing
    dumpkey            Dump a key in text form
    forgecert          Forge an X.509 certificate
```
[//]: # (End of summary -- auto-generated, do not edit!)

# Dependencies
x509sak requires Python3, pyasn1 and pyasn1_modules support. It also relies on
OpenSSL. If you want graph support, then you also need to install the Graphviz
package as well.

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
                               [--outform {rootonly,intermediates,fullchain,all-except-root,multifile}]
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
  --outform {rootonly,intermediates,fullchain,all-except-root,multifile}
                        Specifies what to write into the output file. Possible
                        options are rootonly, intermediates, fullchain, all-
                        except-root, multifile. Default is fullchain. When
                        specifying multifile, a %d format must be included in
                        the filename to serve as a template; typical printf-
                        style formatting can be used of course (e.g., %02d).
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
                        Specifies the output format. Can be one of dot, png,
                        ps, pdf, defaults to dot.
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
usage: ./x509sak.py createca [-k keyspec] [-p capath] [-s subject] [-d days]
                             [-h alg] [--serial serial] [-f] [-v] [--help]
                             capath

Create a new certificate authority (CA)

positional arguments:
  capath                Directory to create the new CA in.

optional arguments:
  -k keyspec, --keytype keyspec
                        Private key type to generate for the new CA. Defaults
                        to ecc:secp384r1.
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
                        Hash function to use for signing. Defaults to sha256.
  --serial serial       Serial number to use for root CA certificate.
                        Randomized by default.
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
usage: ./x509sak.py createcsr [-k keyspec]
                              [-t {rootca,ca,tls-server,tls-client}]
                              [-s subject] [-d days] [-h alg] [--san-dns FQDN]
                              [--san-ip IP] [--extension key=value] [-f]
                              [-c capath] [-v] [--help]
                              in_key_filename out_filename

Create a new certificate signing request (CSR) or certificate

positional arguments:
  in_key_filename       Filename of the input private key.
  out_filename          Filename of the output certificate signing request or
                        certificate.

optional arguments:
  -k keyspec, --keytype keyspec
                        Private key type to generate for the certificate or
                        CSR. By default, it is assumed the private key has
                        created beforehand.
  -t {rootca,ca,tls-server,tls-client}, --template {rootca,ca,tls-server,tls-client}
                        Template to use for determining X.509 certificate
                        extensions. Can be one of rootca, ca, tls-server, tls-
                        client. By default, no extensions are included except
                        for SAN.
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
usage: ./x509sak.py signcsr [-t {rootca,ca,tls-server,tls-client}]
                            [-s subject] [--san-dns FQDN] [--san-ip IP]
                            [-d days] [-h alg] [-f] [-v] [--help]
                            capath in_csr_filename out_crt_filename

Make a certificate authority (CA) sign a crtificate signing request (CSR) and
output the certificate

positional arguments:
  capath                Directory of the signing CA.
  in_csr_filename       Filename of the input certificate signing request.
  out_crt_filename      Filename of the output certificate.

optional arguments:
  -t {rootca,ca,tls-server,tls-client}, --template {rootca,ca,tls-server,tls-client}
                        Template to use for determining X.509 certificate
                        extensions. Can be one of rootca, ca, tls-server, tls-
                        client. By default, no extensions are included except
                        for SAN.
  -s subject, --subject-dn subject
                        Certificate's subject distinguished name. Defaults to
                        the subject given in the CSR.
  --san-dns FQDN        Subject Alternative DNS name to include in the
                        certificate. Can be specified multiple times.
  --san-ip IP           Subject Alternative IP address to include in the CRT.
                        Can be specified multiple times.
  -d days, --validity-days days
                        Number of days that the newly created certificate will
                        be valid for. Defaults to 365 days.
  -h alg, --hashfnc alg
                        Hash function to use for signing. Defaults to the
                        default hash function specified in the CA config.
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
                                 [--accept-unusable-key] [-o file] [-f] [-v]
                                 [--help]

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
                              [-f] [-v] [--help]
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
  -f, --force           Overwrite key/certificate files.
  -v, --verbose         Increase verbosity level. Can be specified multiple
                        times.
  --help                Show this help page.
```
[//]: # (End of cmd-forgecert -- auto-generated, do not edit!)

# License
GNU GPL-3.
