[![Godoc](https://godoc.org/github.com/Tensai75/go-fpe-bytes?status.svg)](http://godoc.org/github.com/Tensai75/go-fpe-bytes) [![License](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# go-fpe-bytes - Byte-Only Format Preserving FPE FF1 Encryption Implementation in Go

**Fork Notice**: This package is forked from [https://github.com/vdparikhrh/fpe](https://github.com/vdparikhrh/fpe) and has been modified to work exclusively with byte slices instead of Unicode strings. The key changes include:

- **Byte-only operation**: All input/output uses `[]byte` instead of `string`
- **256-byte alphabet restriction**: Maximum alphabet size limited to 256 bytes (0x00-0xFF)
- **Enhanced ASCII codec**: Optimized for raw byte processing without UTF-8/Unicode overhead
- **Simplified implementation**: Removed Unicode complexity while maintaining cryptographic security

This makes the package ideal for applications that need format-preserving encryption on binary data or when working with 8-bit character encodings.

A byte-only implementation of the NIST approved Format Preserving Encryption (FPE) FF1 algorithm in Go.

[NIST Recommendation SP 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)

This follows the FF1 scheme for Format Preserving Encryption outlined in the NIST Recommendation, released in March 2016. It builds on and formalizes (differing from but remaining mathematically equivalent to) the FFX-A10 scheme by Bellare, Rogaway and Spies as defined [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec.pdf) and [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf).

**Note about FF2**: FF2 was originally NOT recommended by NIST, but it is under review again as DFF. You can read about it [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/dff/dff-ff2-fpe-scheme-update.pdf).

**Note about FF3**: FF3 support has been removed from this package as NIST has concluded that FF3 is no longer suitable as a general-purpose FPE method due to [recent cryptanalysis](https://csrc.nist.gov/News/2017/Recent-Cryptanalysis-of-FF3).

## Testing

There are some official [test vectors](http://csrc.nist.gov/groups/ST/toolkit/examples.html) for FF1 provided by NIST, which are used for testing in this package (converted to work with byte slices).

To run unit tests on this implementation with all test vectors from the NIST link above, run the built-in tests:

`go test -v github.com/Tensai75/go-fpe-bytes/ff1`

To run only benchmarks:

`go test -v -bench=. -run=NONE github.com/Tensai75/go-fpe-bytes/ff1`

## Example Usage

The example code below can help you get started. Copy it into a file called `main.go`, and run it with `go run main.go`.

```golang
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/Tensai75/go-fpe-bytes/ff1"
)

// panic(err) is just used for example purposes.
func main() {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("D8E7920AFA330A73")
	if err != nil {
		panic(err)
	}

	// The alphabet can contain up to 256 unique bytes (0x00-0xFF).
	// Here we use printable ASCII characters as an example.
	alphabet := []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	// Create a new FF1 cipher "object"
	// Alphabet defines the supported byte set, and 8 is the tweak length.
	FF1, err := ff1.NewCipherWithAlphabet(alphabet, 8, key, tweak)
	if err != nil {
		panic(err)
	}

	original := []byte("123456789")

	// Call the encryption function on example data
	ciphertext, err := FF1.Encrypt(original)
	if err != nil {
		panic(err)
	}

	plaintext, err := FF1.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("Original:", string(original))
	fmt.Println("Ciphertext:", string(ciphertext))
	fmt.Println("Plaintext:", string(plaintext))
}
```

### Working with Binary Data

```golang
// Example with binary data (all 256 possible byte values)
func binaryExample() {
	key, _ := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")
	tweak, _ := hex.DecodeString("D8E7920AFA330A73")

	// Create alphabet with all possible byte values 0-255
	alphabet := make([]byte, 256)
	for i := 0; i < 256; i++ {
		alphabet[i] = byte(i)
	}

	FF1, err := ff1.NewCipherWithAlphabet(alphabet, 8, key, tweak)
	if err != nil {
		panic(err)
	}

	// Encrypt binary data
	original := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	ciphertext, _ := FF1.Encrypt(original)
	plaintext, _ := FF1.Decrypt(ciphertext)

	fmt.Printf("Original: %x\n", original)
	fmt.Printf("Ciphertext: %x\n", ciphertext)
	fmt.Printf("Plaintext: %x\n", plaintext)
}
```

## Usage notes

There is a [FIPS Document](http://csrc.nist.gov/groups/STM/cmvp/documents/fips140-2/FIPS1402IG.pdf) that contains`Requirements for Vendor Affirmation of SP 800-38G` on page 155.

There are some patent related details for FF1 and FF3 as Voltage Security (which was acquired by what is now HP Enterprise) originally developed FFX, which became FF1. They provided NIST with a [Letter of Assurance](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-voltage-ip.pdf) on the matter.

It can be used as part of sensitive data tokenization, especially in regards to PCI and cryptographically reversible tokens. This implementation does not provide any gaurantees regarding PCI DSS or other validation.

It's important to note that, as with any cryptographic package, managing and protecting the key appropriately to your situation is crucial. This package does not provide any guarantees regarding the key in memory.

## Implementation Notes

This byte-only fork was written with the following additional goals:

- **Byte-only operation**: Eliminate Unicode/UTF-8 complexity by working directly with byte slices
- **256-byte alphabet limit**: Restrict alphabet to 0x00-0xFF for optimal performance and simplicity
- **Enhanced performance**: Remove string conversion overhead by processing bytes directly
- **Binary data support**: Enable format-preserving encryption on any binary data

### Key Differences from Original

- **Input/Output**: Uses `[]byte` instead of `string` for all plaintext, ciphertext, and alphabet
- **Alphabet Size**: Limited to maximum 256 bytes (full 8-bit range: 0x00-0xFF)
- **Performance**: Improved performance by eliminating UTF-8 encoding/decoding overhead
- **Radix Support**: Supports any radix from 2 to 256 (vs. original limit of 36 then 62)
- **Memory Efficiency**: Uses `uint8` arrays instead of `uint16` for internal processing

### Compatibility

This implementation maintains full cryptographic compatibility with the NIST FF1 specification while optimizing for byte-based operations. Test vectors from NIST are converted to byte format and all pass successfully.

The only cryptographic primitive used for FF1 is AES. This package uses Go's standard library's `crypto/aes` package for this. Note that while it technically uses AES-CBC mode, in practice it almost always is meant to act on a single-block with an IV of 0, which is effectively ECB mode. AES is also the only block cipher function that works at the moment, and the only allowed block cipher to be used for FF1/FF3, as per the spec.

In the spec, it says that the radix and minimum length (minLen) of the message should be such that `radix^minLen >= 100`. In Appendix A, it mentions this is to prevent a generic MITM against the Feistel structure, but for better security, radix^minLen >= 1,000,000. In `ff1.go` and `ff3.go` there is a `const` called `FEISTEL_MIN` that can be changed to a sufficient value (like 1,000,000), but by default, it only follows the bare spec.

Regarding how the "tweak" is used as input: I interpreted the spec as setting the tweak in the initial `NewCipher` call, instead of in each `Encrypt` and `Decrypt` call. In one sense, it is similar to passing an IV or nonce once when creating an encryptor object. It's likely that this can be modified to do it in each `Encrypt`/`Decrypt` call, if that is more applicable to what you are building.

## Related Implementations

This implementation is based on work of Vishal Parikh ([https://github.com/vdparikhrh/fpe](https://github.com/vdparikhrh/fpe)), which in turn was derived from Capital One's implementation.

Other implementations include:

- [Original Capital One implementation](https://github.com/capitalone/fpe) - String-based with Unicode support
- [Vishal Parikh's implementation](https://github.com/vdparikhrh/fpe) - String-based with Unicode support and custom alphabet
- [Roasbeef's implementation](https://github.com/Roasbeef/perm-crypt) - Based on earlier FFX spec
- [Java implementation](https://sourceforge.net/projects/format-preserving-encryption/) - Used for testing and comparison

### Why This Fork?

This byte-only fork addresses specific use cases where:

- Working with binary data or 8-bit encodings
- Need maximum performance without Unicode overhead
- Want to encrypt data that doesn't map cleanly to Unicode strings
- Require support for all 256 possible byte values (including null bytes, control characters, etc.)
