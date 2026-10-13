#!/bin/sh
# Generates an example CA for the client certificates: an ECDSA P-256 key and a
# self-signed CA certificate allowed to sign certificates and CRLs.
# For development and testing; use a properly protected CA in production.
#
# Usage: scripts/example-ca.sh [output dir] [common name] [days]
#   defaults: ./ca  "authentik-manager example CA"  3650
#
# Then set CA_CERT_FILE=<dir>/ca.crt and CA_KEY_FILE=<dir>/ca.key.
set -eu

dir=${1:-ca}
cn=${2:-authentik-manager example CA}
days=${3:-3650}

command -v openssl >/dev/null 2>&1 || {
	echo "openssl is required" >&2
	exit 1
}
case $days in
'' | *[!0-9]* | 0*)
	echo "days must be a positive number, got '$days'" >&2
	exit 1
	;;
esac
if [ -e "$dir/ca.key" ] || [ -e "$dir/ca.crt" ]; then
	echo "$dir/ca.key or $dir/ca.crt already exists; not overwriting" >&2
	exit 1
fi

mkdir -p "$dir"
# The key is created readable by the owner only.
umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/ca.key"
umask 022
openssl req -x509 -new -key "$dir/ca.key" -out "$dir/ca.crt" -days "$days" -sha256 \
	-subj "/CN=$cn" \
	-addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-addext "subjectKeyIdentifier=hash"

openssl x509 -in "$dir/ca.crt" -noout -subject -enddate -fingerprint -sha256
cat <<MSG

Created $dir/ca.crt and $dir/ca.key. Configure the app with:

  CA_CERT_FILE=$dir/ca.crt
  CA_KEY_FILE=$dir/ca.key
MSG
