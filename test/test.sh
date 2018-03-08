#!/bin/bash

set -e
dir=`dirname $0`
port=443
cd $dir
sudo ./tls_test -C -S -p $port -c pem/ser_cacert.pem,pem/cli_cacert.pem -k pem/ser_privkey.pem,pem/cli_privkey.pem
sudo ./tls_test -S -p $port -c pem/ser_cacert.pem,pem/cli_cacert.pem -k pem/ser_privkey.pem,pem/cli_privkey.pem
