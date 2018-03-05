#!/bin/bash -e

mkdir -p output >/dev/null 2>&1
cd output

# Create a root CA
../x509sak.py createca -f root_ca

# Create an intermediate CA that is signed by that root CA
../x509sak.py createca -f --subject "/CN=Intermediate" -h sha384 -p root_ca foo_ca

# Create a CSR
../x509sak.py createcsr -k ecc:secp256r1 -f client1.key client1.csr

# Create another CSR with Subject Alternative Names
../x509sak.py createcsr -k ecc:secp256r1 --san-dns foobar --san-ip 1.2.3.4 -s "/CN=moo koo" -f client2.key client2.csr

# Sign the first CSR by the root CA
../x509sak.py signcsr -f root_ca client1.csr client1.crt

# Sign the second CSR by the root CA
../x509sak.py signcsr -h sha384 -d 700 --san-dns foobar --san-ip 1.2.3.4 -f root_ca -t tls-client client2.csr client2.crt

# Directly create a certificate, signed by the intermediate CA, without creating a CSR first
../x509sak.py createcsr --create-crt foo_ca -k ecc:secp256r1 --san-dns foobar --san-ip 1.2.3.4 -s "/CN=moo koo 3" -f client3.key client3.crt

# Directly create another certificate with a custom X.509 extension, signed by the intermediate CA, without creating a CSR first
../x509sak.py createcsr --create-crt foo_ca -k ecc:secp256r1 --san-dns foobar --san-ip 1.2.3.4 --extension "1.2.3.4.5=DER:00:11:22:33" -s "/CN=moo koo 4" -f client3.key client4.crt

# Revoke the last generated certificate
../x509sak.py revokecrt foo_ca client4.crt
