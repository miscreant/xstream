# xstream.go [![Build Status][build-shield]][build-link] [![GoDoc][godoc-shield]][godoc-link] [![Go Report Card][goreport-shield]][goreport-link] [![MIT licensed][license-shield]][license-link] [![Gitter Chat][gitter-image]][gitter-link]

[build-shield]: https://secure.travis-ci.org/miscreant/xstream.svg?branch=master
[build-link]: https://travis-ci.org/miscreant/xstream
[godoc-shield]: https://godoc.org/github.com/miscreant/xstream/go?status.svg
[godoc-link]: https://godoc.org/github.com/miscreant/xstream/go
[goreport-shield]: https://goreportcard.com/badge/github.com/miscreant/xstream
[goreport-link]: https://goreportcard.com/report/github.com/miscreant/xstream
[license-shield]: https://img.shields.io/badge/license-MIT/Apache2.0-blue.svg
[license-link]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
[gitter-image]: https://badges.gitter.im/badge.svg
[gitter-link]: https://gitter.im/miscreant/Lobby

**XSTREAM** (pronounced *"extreme!"*) is a public key encryption system combining
X25519 Elliptic Curve Diffie-Hellman ([RFC 7748]) with the [STREAM] construction.

The implementations in this repository are built on top of the
[Miscreant] misuse-resistant symmetric encryption library, which provides
the [AES-SIV] and [AES-PMAC-SIV] algorithms.

[More information on XSTREAM](https://github.com/miscreant/xstream/wiki/XSTREAM)
is available in the Wiki.

[RFC 7748]: https://tools.ietf.org/html/rfc7748
[STREAM]: https://github.com/miscreant/miscreant/wiki/STREAM
[Miscreant]: https://github.com/miscreant/miscreant
[AES-SIV]: https://github.com/miscreant/miscreant/wiki/AES-SIV
[AES-PMAC-SIV]: https://github.com/miscreant/miscreant/wiki/AES-PMAC-SIV

## Help and Discussion

Have questions? Want to suggest a feature or change?

* [Gitter]: web-based chat about miscreant projects including **miscreant.rb**
* [Google Group]: join via web or email ([miscreant-crypto+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/miscreant/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/miscreant-crypto
[miscreant-crypto+subscribe@googlegroups.com]: mailto:miscreant-crypto+subscribe@googlegroups.com?subject=subscribe

## Security Notice

Though this library is written by cryptographic professionals, it has not
undergone a thorough security audit, and cryptographic professionals are still
humans that make mistakes.

Use this library at your own risk.

## Documentation

[Please see the XSTREAM Wiki](https://github.com/miscreant/xstream/wiki/Go-Documentation)
for API documentation.

## Code of Conduct

We abide by the [Contributor Covenant][cc] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md].

[cc]: https://contributor-covenant.org
[CODE_OF_CONDUCT.md]: https://github.com/miscreant/xstream/blob/master/CODE_OF_CONDUCT.md

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/miscreant/xstream.

## License

Copyright (c) 2017-2018 [The Miscreant Developers][AUTHORS].

All XSTREAM libraries are licensed under either of:

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

[AUTHORS]: https://github.com/miscreant/miscreant/blob/master/AUTHORS.md
