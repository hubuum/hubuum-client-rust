#!/bin/sh
set -eu

openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
    -subj '/CN=Hubuum integration LDAP CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout /certs/ca.key -out /certs/ca.crt >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes \
    -subj '/CN=planetexpress.com' \
    -keyout /certs/ldap.key -out /tmp/ldap.csr >/dev/null 2>&1
printf '%s\n' \
    'subjectAltName=DNS:planetexpress.com' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' >/tmp/ldap.ext
openssl x509 -req -in /tmp/ldap.csr \
    -CA /certs/ca.crt -CAkey /certs/ca.key -CAcreateserial \
    -days 2 -sha256 -extfile /tmp/ldap.ext \
    -out /certs/ldap.crt >/dev/null 2>&1
chmod 600 /certs/ca.key /certs/ldap.key
