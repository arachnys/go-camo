FROM scratch

ARG BUILD_DATE
ARG VCS_REF
LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://www.github.com/arachnys/go-camo" \
      org.label-schema.docker.cmd="docker run --rm -p 8080:8080 arachnysdocker/go-camo -k <hmac key>" \
      maintainer="Arachnys <techteam@arachnys.com>"

COPY go-camo /
ENTRYPOINT ["/go-camo"]
