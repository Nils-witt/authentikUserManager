#!/bin/sh
# Builds the opsi package authentik-manager-cert_<version>.opsi in this
# directory: copies scripts/Update-ServiceCertificate.ps1 into the package and
# runs opsi-makepackage in a container built from ./Dockerfile. Arguments are
# passed to opsi-makepackage, e.g. --package-version 2; without any, an
# existing package of the same version is overwritten (--keep-versions).
# opsi-makepackage also writes OPSI/control and normalizes OPSI/control.toml.
set -eu

cd "$(dirname "$0")"
image=authentik-manager-opsi-makepackage

# The copy is ignored by git, so a fresh clone lacks the directory.
mkdir -p CLIENT_DATA/files
cp ../scripts/Update-ServiceCertificate.ps1 CLIENT_DATA/files/

docker build --quiet --tag "$image" . >/dev/null

[ $# -eq 0 ] && set -- --keep-versions

# opsi-makepackage may ask before overwriting a package, so keep a terminal when there is one.
tty_flags=-i
[ -t 0 ] && tty_flags=-it

docker run --rm $tty_flags \
	--user "$(id -u):$(id -g)" \
	--env HOME=/tmp \
	--volume "$(pwd):/work" \
	"$image" "$@"
