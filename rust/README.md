# xstream.rs

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
[![MIT licensed][license-image]][license-link]
[![Gitter Chat][gitter-image]][gitter-link]

[crate-image]: https://img.shields.io/crates/v/xstream.svg
[crate-link]: https://crates.io/crates/xstream
[docs-image]: https://docs.rs/xstream/badge.svg
[docs-link]: https://docs.rs/xstream/
[build-image]: https://secure.travis-ci.org/miscreant/xstream.svg?branch=master
[build-link]: http://travis-ci.org/miscreant/xstream
[license-image]: https://img.shields.io/badge/license-MIT/Apache2.0-blue.svg
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

## Requirements

This library presently requires the following:

* **x86_64** CPU architecture
* Rust **nightly** compiler

This library implements the AES cipher using the [aesni] crate, which
uses the [Intel AES-NI] CPU instructions to provide a fast, constant-time
hardware-based implementation. No software-only implementation of AES is
provided. Additionally it includes Intel assembly language implementations of
certain secret-dependent functions which have verified constant-time operation.

Supporting stable Rust will require upstream changes in the [aesni] crate,
which is nightly-only due to its use of inline assembly.

[aesni]: https://github.com/RustCrypto/block-ciphers
[Intel AES-NI]: https://software.intel.com/en-us/blogs/2012/01/11/aes-ni-in-laymens-terms

## Help and Discussion

Have questions? Want to suggest a feature or change?

* [Gitter]: web-based chat about **Miscreant** projects including **miscreant.rs**
* [Google Group]: join via web or email ([miscreant-crypto+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/miscreant/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/miscreant-crypto
[miscreant-crypto+subscribe@googlegroups.com]: mailto:miscreant-crypto+subscribe@googlegroups.com?subject=subscribe

## Documentation

[Please see the Rustdocs on docs.rs][docs-link] for API documentation.

## Security Notice

Though this library is written by cryptographic professionals, it has not
undergone a thorough security audit, and cryptographic professionals are still
humans that make mistakes.

This library makes an effort to use constant time operations throughout its
implementation, however actual constant time behavior has not been verified.

Use this library at your own risk.

## Code of Conduct

We abide by the [Contributor Covenant][cc] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md].

[cc]: https://contributor-covenant.org
[CODE_OF_CONDUCT.md]: https://github.com/miscreant/xstream/blob/master/CODE_OF_CONDUCT.md

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/miscreant/xstream.

## License

Copyright (c) 2017 [The Miscreant Developers][AUTHORS].

All XSTREAM libraries are licensed under either of:

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

[AUTHORS]: https://github.com/miscreant/miscreant/blob/master/AUTHORS.md
