# opsi-makepackage from the opsi 4.3 stable repository, for opsi/build.sh.
FROM debian:12-slim

ARG OPSI_REPO=https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.3:/stable/Debian_12

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates curl gpg \
	&& curl -fsSL "$OPSI_REPO/Release.key" | gpg --dearmor -o /usr/share/keyrings/opsi.gpg \
	&& echo "deb [signed-by=/usr/share/keyrings/opsi.gpg] $OPSI_REPO/ /" > /etc/apt/sources.list.d/opsi.list \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends opsi-utils \
	&& apt-get purge -y curl gpg && apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENTRYPOINT ["opsi-makepackage"]
