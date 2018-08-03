Base58Check
===========

Base58Check is a C# implementation of [Base58 Checked Encoding](https://en.bitcoin.it/wiki/Base58Check_encoding), based on a [public domain Gist](https://gist.github.com/CodesInChaos/3175971) by @CodesInChaos.

In short, Base58 is a encoding algorithm similar to Base64, removing certain characters that cause issues with URLs, and cause confusion because of how similar they look in certain fonts. Base58Check adds a 4 byte checksum to validate that the data hasn't been altered in transmission. This checksum isn't suitable to perform cryptographic validation, but is does detect accidental corruption.

Want to support development? Consider donating via Bitcoin to `14jumFDmuVkLiAt4TgyKt17SWHtPRbkcLr` - all donations, no matter how small are appreciated.

## Installation

[NuGet Package](https://www.nuget.org/packages/Base58Check/)

## Public Interface

* **`Base58CheckEncoding.Encode(byte[])`** - Encodes data with a 4-byte checksum
* **`Base58CheckEncoding.Decode(string)`** - Decodes data in Base58Check format (with 4 byte checksum)
* **`Base58CheckEncoding.EncodePlain(byte[])`** - Encodes data in plain Base58, without any checksum
* **`Base58CheckEncoding.DecodePlain(string)`** - Decodes data in plain Base58, without any checksum

The `Encode*` methods both expect a byte array of arbitrary length; as the entire payload to encode must be loaded into memory, an `OutOfMemoryException` may be thrown for large payloads. The `Decode*` methods will throw a `FormatException` if the string passed in isn't in a valid Base58 format; the `Decode` method will also throw the `FormatException` if the checksum verification fails.

## License

This software is released to the public domain.

See LICENSE for more information.
