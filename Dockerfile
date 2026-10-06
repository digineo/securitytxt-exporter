# Built by goreleaser (dockers_v2), which provides the binary per platform.
FROM gcr.io/distroless/static-debian13:nonroot

ARG TARGETPLATFORM
LABEL org.opencontainers.image.source=https://github.com/digineo/securitytxt-exporter

COPY $TARGETPLATFORM/securitytxt-exporter /usr/bin/securitytxt-exporter

EXPOSE 2610
ENTRYPOINT ["/usr/bin/securitytxt-exporter"]
CMD ["-web.listen-address", ":2610"]
