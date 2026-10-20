# Third-Party Notices

This repository vendors the following third-party components:

## libcurl

- Location: `deps/include/curl/` (headers), `deps/lib/libcurl.a` (static library, built by `scripts/build-static-deps.sh`)
- Upstream: https://curl.se/
- License: curl license (MIT-style; see https://curl.se/docs/legal/curl-distribution.html)
- The static archive is a convenience for building the Linux implant. Builds can regenerate it with `scripts/build-static-deps.sh`.

All other code in this repository is original to the Jager-C2 project and is licensed under the MIT License (see LICENSE).