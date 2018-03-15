# go-camo

[![Build Status](https://travis-ci.org/arachnys/go-camo.png?branch=master)](https://travis-ci.org/arachnys/go-camo)

An SSL/TLS proxy for insecure static assets to circumvent mixed content warnings. Based on [`go-camo`][1], and [`camo`][2].


## About

This is [Arachnys'][3] version of [`go-camo`][1].
See https://github.com/cactus/go-camo/ for more information.

### Differences from Upstream

The fundamental value proposition remains the same as the original project.
That is, to proxy non-secure images over SSL/TLS, particularly to circumvent mixed content warnings on secure pages.

There are however, some crucial changes, and improvements:

- Support for proxying fonts, stylesheets, and URLs in stylesheets
- Support for proxying gzipped stylesheets
- Support for protocol-relative URLs / URLs without a scheme
- Support for proxying data URIs
- Support for proxying bad SSL/TLS URIs
- Higher default timeout
- Sentry for crash reporting, and aggregation
- End-to-end health check endpoint (`/health`)
- Go's `dep` (and vanilla tooling) is used instead of `gb` for dependency management
- `goreleaser` is used instead of `gb`, and the `Makefile` for building binaries
- Support for graceful shutdown via [termination signals][8]
- Support for [Docker][9] (`docker pull arachnysdocker/go-camo`)

### Differences from Camo

See https://github.com/cactus/go-camo#differences-from-camo.


## Usage

Releases are managed by [goreleaser][5].

### Pre-built binaries

Download the tarball appropriate for your OS from [releases][4].
Extract, and copy files to desired locations.

### Docker

```sh
# Server
docker run -t --rm -p 8080:8080 arachnysdocker/go-camo:<tag> -k <hmac key>

# URL tool
docker run -t --rm arachnysdocker/go-camo-url-tool:<tag> -k <hmac key>
```

Set `<tag>` to a version in the [releases][4] or set it to `latest`. For stability, we do not recommend using `latest` as there may be breaking changes. Use a [tagged release][4].


## Configuration

```sh
# Binary
go-camo -h

# Docker
docker run -t --rm -p 8080:8080 arachnysdocker/go-camo:<tag> -h
```

**Environment Variables:**

- `GOCAMO_HMAC`: HMAC key used for encoding / decoding URLs


## Development

Run `make` to show all available targets. Alternatively, see [`Makefile`][6].

To get an idea of what is needed for `localhost` development, see [`.travis.yml`][7].


[1]: https://github.com/cactus/go-camo/
[2]: https://github.com/atmos/camo
[3]: https://www.arachnys.com/
[4]: https://github.com/arachnys/go-camo/releases
[5]: https://github.com/goreleaser/goreleaser
[6]: ./Makefile
[7]: ./.travis.yml
[8]: https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html
[9]: https://www.docker.com/
