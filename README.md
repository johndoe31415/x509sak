# x509sak
[![Build Status](https://travis-ci.org/johndoe31415/x509sak.svg?branch=master)](https://travis-ci.org/johndoe31415/x509sak)

X.509 Swiss Army Knife (x509sak) is a toolkit written in Python that acts as a
boilerplate on top of OpenSSL to ease creation of X.509 certificates,
certificate signing requests and CAs. It can automatically find CA chains and
output them in a specifically desired format, graph CA hierarchies and more.

The tool is used similarly to OpenSSL in its syntax. The help page is meant to
be comprehensive and self-explanatory. These are the currently available commands:

```
$ ./x509sak.py
Error: No command supplied.
Syntax: ./x509sak.py [command] [options]

Available commands:
    buildchain         Build a certificate chain
    graph              Graph a certificate pool
    findcrt            Find a specific certificate
    createca           Create a new certificate authority (CA)
    createcsr          Create a new certificate signing request (CSR) or certificate
    signcsr            Make a certificate authority (CA) sign a crtificate signing request (CSR) and output the certificate
    revokecrt          Revoke a specific certificate

Options vary from command to command. To receive further info, type
    ./x509sak.py [command] --help
```

# Dependencies
x509sak requires Python3, pyasn1 and pyasn1_modules support. If you want
graphs, then you also need GraphViz support too.

## buildca
```
usage: ./x509sak.py buildchain [-s path] [--inform {pem,der}]
                               [--order-leaf-to-root] [--allow-partial-chain]
                               [--outform {rootonly,intermediates,fullchain,all-except-root,multifile}]
                               -o file [-v]
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
  --outform {rootonly,intermediates,fullchain,all-except-root,multifile}
                        Specifies what to write into the output file. Possible
                        options are rootonly, intermediates, fullchain, all-
                        except-root, multifile. Default is fullchain. When
                        specifying multifile, a %d format must be included in
                        the filename to serve as a template; typical printf-
                        style formatting can be used of course (e.g., %02d).
  -o file, --outfile file
                        Specifies the output filename. Mandatory argument.
  -v, --verbose         Increase verbosity level.
```

## graph
```
usage: ./x509sak.py graph [-f {dot,png,ps,pdf}] -o file [-v]
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
  -v, --verbose         Increase verbosity level.
```

## findcrt
```
usage: ./x509sak.py findcrt [-h hash] [-v] crtsource [crtsource ...]

Find a specific certificate

positional arguments:
  crtsource             Certificate file (in PEM format) or directory
                        (conainting PEM-formatted .pem or .crt files) which
                        should be included in the search.

optional arguments:
  -h hash, --hashval hash
                        Find only certificates with a particular hash prefix.
  -v, --verbose         Increase verbosity level.
```

## createca
```
usage: ./x509sak.py createca [-k keyspec] [-p capath] [-s subject] [-d days]
                             [-h alg] [--serial serial] [-f] [-v]
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
  -v, --verbose         Increase verbosity level.
```

## createcsr
```
usage: ./x509sak.py createcsr [-k keyspec]
                              [-t {rootca,ca,tls-server,tls-client}]
                              [-s subject] [-d days] [-h alg] [--san-dns FQDN]
                              [--san-ip IP] [--extension key=value] [-f]
                              [-c capath] [-v]
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
  -v, --verbose         Increase verbosity level.
```

## signcsr
```
usage: ./x509sak.py signcsr [-t {rootca,ca,tls-server,tls-client}]
                            [-s subject] [--san-dns FQDN] [--san-ip IP]
                            [-d days] [-h alg] [-f] [-v]
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
  -v, --verbose         Increase verbosity level.
```

## revokecrt
```
usage: ./x509sak.py revokecrt [-v] capath crt_filename

Revoke a specific certificate

positional arguments:
  capath         CA which created the certificate.
  crt_filename   Filename of the output certificate.

optional arguments:
  -v, --verbose  Increase verbosity level.
```

# License
GNU GPL-3.
