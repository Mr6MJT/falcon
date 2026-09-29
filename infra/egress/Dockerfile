# Gate 3 egress gateway — programs an nftables allow-list and NATs only in-scope egress.
FROM alpine:3.20
RUN apk add --no-cache nftables iproute2 coreutils
COPY infra/egress/entrypoint.sh /usr/local/bin/gate3
RUN chmod +x /usr/local/bin/gate3
ENTRYPOINT ["/usr/local/bin/gate3"]
