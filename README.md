# XSTREAM [![Build Status][build-image]][build-link] [![MIT Licensed][license-image]][license-link] [![Gitter Chat][gitter-image]][gitter-link]

[build-image]: https://secure.travis-ci.org/miscreant/xstream.svg?branch=master
[build-link]: http://travis-ci.org/miscreant/xstream
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
[gitter-image]: https://badges.gitter.im/badge.svg
[gitter-link]: https://gitter.im/miscreant/Lobby

A public-key encryption system supporting streaming message encryption/decryption.

## What is XSTREAM?

**XSTREAM** (pronounced *"extreme!"*) is a public key encryption system combining
X25519 Elliptic Curve Diffie-Hellman ([RFC 7748]) with the [STREAM] construction.

The implementations in this repository are built on top of the
[Miscreant] misuse-resistant symmetric encryption library, which provides
the [AES-SIV] and [AES-PMAC-SIV] algorithms.

[RFC 7748]: https://tools.ietf.org/html/rfc7748
[STREAM]: https://github.com/miscreant/miscreant/wiki/STREAM
[Miscreant]: https://github.com/miscreant/miscreant
[AES-SIV]: https://github.com/miscreant/miscreant/wiki/AES-SIV
[AES-PMAC-SIV]: https://github.com/miscreant/miscreant/wiki/AES-PMAC-SIV

### Key Derivation Function

<img alt="XSTREAM KDF" src="https://miscreant.io/images/xstream-kdf.svg" width="600px">

### [STREAM] Construction

<img alt="XSTREAM KDF" src="https://miscreant.io/images/stream.svg" width="600px">

NOTE: As **XSTREAM** derives a unique symmetric key every time the KDF is
invoked, and also supports an optional salt value passed directly to HKDF,
the `N` parameter passed to the underlying **STREAM** construction is fixed to
all-zeroes.

The API is explicitly designed to prevent encrypting more than one message under
the same ephemeral key.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/miscreant/xstream

## Copyright

Copyright (c) 2017 [The Miscreant Developers][AUTHORS].
Distributed under the MIT license. See [LICENSE.txt] for further details.

Some language-specific subprojects include sources from other authors with more
specific licensing requirements, though all projects are MIT licensed.
Please see the respective **LICENSE.txt** files in each project for more
information.

[AUTHORS]: https://github.com/miscreant/miscreant/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
