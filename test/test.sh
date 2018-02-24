#!/bin/bash

set -e
./tls_test -C -S -c pem/ser_cacert.pem,pem/cli_cacert.pem -k pem/ser_privkey.pem,pem/cli_privkey.pem
./tls_test -S -c pem/ser_cacert.pem,pem/cli_cacert.pem -k pem/ser_privkey.pem,pem/cli_privkey.pem
