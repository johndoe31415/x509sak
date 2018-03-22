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
../x509sak.py revokecrt -vvv foo_ca client4.crt

# Generate an example RSA key and dump its public/private key
openssl genrsa -out key_rsa.key 512
openssl rsa -in key_rsa.key -pubout -out pubkey_rsa.key
../x509sak.py dumpkey key_rsa.key
../x509sak.py dumpkey -p pubkey_rsa.key

# Generate an example ECC key and dump its public/private key
openssl ecparam -genkey -name secp256r1 -out key_ecc.key
openssl ec -in key_ecc.key -pubout -out pubkey_ecc.key
../x509sak.py dumpkey -t ecc key_ecc.key
../x509sak.py dumpkey -p pubkey_ecc.key

# Forge a chain of certificates
cat root_ca/CA.crt foo_ca/CA.crt client3.crt >original.crt
../x509sak.py forgecert original.crt
../x509sak.py buildchain -s forged_00.crt -s forged_01.crt forged_02.crt
