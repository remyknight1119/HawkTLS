#!/bin/bash

set -e
dir=`dirname $0`
sample=$1
port=443
cert=pem/ser_cacert.pem,pem/cli_cacert.pem
key=pem/ser_privkey.pem,pem/cli_privkey.pem
cd $dir
if [ ! -z $sample ]; then
    sudo ./tls_test -C -S -p $port -c $cert -k $key
fi
sudo ./tls_test -S -p $port -c $cert -k $key
