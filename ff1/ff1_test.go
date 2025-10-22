/*

SPDX-Copyright: Copyright (c) Capital One Services, LLC
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Capital One Services, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

*/

package ff1

import (
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"testing"
)

// Test vectors taken from here: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF1samples.pdf

// As Golang's sub-tests were introduced in Go 1.7, but this package will work with Go 1.6+, so I'm keeping sub-tests in a separate branch for now.

type testVector struct {
	radix int

	// Key and tweak are both hex-encoded strings
	key        string
	tweak      string
	plaintext  []byte
	ciphertext []byte
}

// Official NIST FF1 Test Vectors
var testVectors = []testVector{
	// AES-128
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"",
		[]byte("0123456789"),
		[]byte("2433477484"),
	},
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"39383736353433323130",
		[]byte("0123456789"),
		[]byte("6124200773"),
	},
	{
		36,
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"3737373770717273373737",
		[]byte("0123456789abcdefghi"),
		[]byte("a9tv40mll9kdu509eum"),
	},

	// AES-192
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
		"",
		[]byte("0123456789"),
		[]byte("2830668132"),
	},
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
		"39383736353433323130",
		[]byte("0123456789"),
		[]byte("2496655549"),
	},
	{
		36,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
		"3737373770717273373737",
		[]byte("0123456789abcdefghi"),
		[]byte("xbj3kv35jrawxv32ysr"),
	},

	// AES-256
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
		"",
		[]byte("0123456789"),
		[]byte("6657667009"),
	},
	{
		10,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
		"39383736353433323130",
		[]byte("0123456789"),
		[]byte("1001623463"),
	},
	{
		36,
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
		"3737373770717273373737",
		[]byte("0123456789abcdefghi"),
		[]byte("xs8a0azh2avyalyzuwd"),
	},
}

func TestEncrypt(t *testing.T) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				t.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				t.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(testVector.radix, 16, key, tweak)
			if err != nil {
				t.Fatalf("Unable to create cipher: %v", err)
			}

			ciphertext, err := ff1.Encrypt(testVector.plaintext)
			if err != nil {
				t.Fatalf("%v", err)
			}

			if !reflect.DeepEqual(ciphertext, testVector.ciphertext) {
				t.Fatalf("\nSample%d\nradix:\t\t%d\nKey:\t\t%s\nTweak:\t\t%s\nPlaintext:\t%v\nCiphertext:\t%v\nExpected:\t%v", sampleNumber, testVector.radix, testVector.key, testVector.tweak, testVector.plaintext, ciphertext, testVector.ciphertext)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				t.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				t.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(testVector.radix, 16, key, tweak)
			if err != nil {
				t.Fatalf("Unable to create cipher: %v", err)
			}

			plaintext, err := ff1.Decrypt(testVector.ciphertext)
			if err != nil {
				t.Fatalf("%v", err)
			}

			if !reflect.DeepEqual(plaintext, testVector.plaintext) {
				t.Fatalf("\nSample%d\nradix:\t\t%d\nKey:\t\t%s\nTweak:\t\t%s\nCiphertext:\t%v\nPlaintext:\t%v\nExpected:\t%v", sampleNumber, testVector.radix, testVector.key, testVector.tweak, testVector.ciphertext, plaintext, testVector.plaintext)
			}
		})
	}
}

// These are for testing long inputs, which are not in the standard test vectors
func TestLong(t *testing.T) {
	key, _ := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")

	tweak, _ := hex.DecodeString("")

	// 16 is an arbitrary number for maxTlen
	ff1, err := NewCipher(36, 16, key, tweak)
	if err != nil {
		t.Fatalf("Unable to create cipher: %v", err)
	}

	plaintext := []byte("xs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyal")

	ciphertext, err := ff1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	decrypted, err := ff1.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !reflect.DeepEqual(plaintext, decrypted) {
		t.Fatalf("Long Decrypt Failed. \n Expected: %v \n Got: %v \n", plaintext, decrypted)
	}
}

// Regression test for issue 14: https://github.com/capitalone/fpe/issues/14
func TestIssue14(t *testing.T) {
	key, _ := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")

	tweak, _ := hex.DecodeString("D8E7920AFA330A73")

	ff1, err := NewCipher(2, 8, key, tweak)
	if err != nil {
		t.Fatalf("Unable to create cipher: %v", err)
	}

	plaintext := []byte("11111010")

	ciphertext, err := ff1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	decrypted, err := ff1.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !reflect.DeepEqual(plaintext, decrypted) {
		t.Fatalf("Issue 14 Decrypt Failed. \n Expected: %v \n Got: %v \n", plaintext, decrypted)
	}
}

// Test with arbitrary byte values including high bytes
func TestByteValues(t *testing.T) {
	key, _ := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")

	tweak, _ := hex.DecodeString("D8E7920AFA330A73")

	// Create alphabet with some binary values
	alphabet := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	ff1, err := NewCipherWithAlphabet(alphabet, 8, key, tweak)
	if err != nil {
		t.Fatalf("Unable to create cipher: %v", err)
	}

	plaintext := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

	ciphertext, err := ff1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	decrypted, err := ff1.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !reflect.DeepEqual(plaintext, decrypted) {
		t.Fatalf("TestByteValues Decrypt Failed. \n Expected: %v \n Got: %v \n", plaintext, decrypted)
	}
}

func TestAlphabetSizes(t *testing.T) {
	// Test with different alphabet sizes from 2 to 256
	key, _ := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")
	tweak, _ := hex.DecodeString("D8E7920AFA330A73")

	for s := 2; s <= 256; s *= 2 { // Test powers of 2: 2, 4, 8, 16, 32, 64, 128, 256
		alphabet := make([]byte, s)
		for i := 0; i < s; i++ {
			alphabet[i] = byte(i)
		}

		ff1, err := NewCipherWithAlphabet(alphabet, 8, key, tweak)
		if err != nil {
			t.Fatalf("Unable to create cipher for alphabet size %d: %v", s, err)
		}

		// Calculate minimum length based on the cipher's requirements
		// For FF1, minimum length = ceil(log(100) / log(radix))
		minLen := int(math.Ceil(math.Log(100) / math.Log(float64(s))))
		testLen := minLen
		if testLen < 10 {
			testLen = 10
		}

		plaintext := make([]byte, testLen)
		for i := 0; i < testLen; i++ {
			plaintext[i] = alphabet[i%s]
		}

		ciphertext, err := ff1.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed for alphabet size %d: %v", s, err)
		}

		decrypted, err := ff1.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt failed for alphabet size %d: %v", s, err)
		}

		if !reflect.DeepEqual(plaintext, decrypted) {
			t.Fatalf("Round-trip failed for alphabet size %d. Expected: %v, Got: %v", s, plaintext, decrypted)
		}
	}
}

// Note: panic(err) is just used for example purposes.
func ExampleCipher_Encrypt() {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("")
	if err != nil {
		panic(err)
	}

	// Create a new FF1 cipher "object"
	// 10 is the radix/base, and 8 is the tweak length.
	FF1, err := NewCipher(10, 8, key, tweak)
	if err != nil {
		panic(err)
	}

	original := []byte("0123456789")

	// Call the encryption function on an example test vector
	ciphertext, err := FF1.Encrypt(original)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(ciphertext))
	// Output: 2433477484
}

// Note: panic(err) is just used for example purposes.
func ExampleCipher_Decrypt() {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("")
	if err != nil {
		panic(err)
	}

	// Create a new FF1 cipher "object"
	// 10 is the radix/base, and 8 is the tweak length.
	FF1, err := NewCipher(10, 8, key, tweak)
	if err != nil {
		panic(err)
	}

	ciphertext := []byte("2433477484")

	// Call the decryption function on an example test vector
	plaintext, err := FF1.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plaintext))
	// Output: 0123456789
}

func BenchmarkNewCipher(b *testing.B) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		b.Run(fmt.Sprintf("Sample%d", sampleNumber), func(b *testing.B) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				b.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			b.ResetTimer()

			// 16 is an arbitrary number for maxTlen
			for n := 0; n < b.N; n++ {
				NewCipher(testVector.radix, 16, key, tweak)
			}
		})
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		b.Run(fmt.Sprintf("Sample%d", sampleNumber), func(b *testing.B) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				b.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(testVector.radix, 16, key, tweak)
			if err != nil {
				b.Fatalf("Unable to create cipher: %v", err)
			}

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				ff1.Encrypt(testVector.plaintext)
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		b.Run(fmt.Sprintf("Sample%d", sampleNumber), func(b *testing.B) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				b.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(testVector.radix, 16, key, tweak)
			if err != nil {
				b.Fatalf("Unable to create cipher: %v", err)
			}

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				ff1.Decrypt(testVector.ciphertext)
			}
		})
	}
}

// This benchmark is for the end-to-end NewCipher, Encryption, Decryption process
// Similar to the examples
func BenchmarkE2ESample7(b *testing.B) {
	testVector := testVectors[6]
	key, err := hex.DecodeString(testVector.key)
	if err != nil {
		b.Fatalf("Unable to decode hex key: %v", testVector.key)
	}

	tweak, err := hex.DecodeString(testVector.tweak)
	if err != nil {
		b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		// 16 is an arbitrary number for maxTlen
		ff1, err := NewCipher(testVector.radix, 16, key, tweak)
		if err != nil {
			b.Fatalf("Unable to create cipher: %v", err)
		}

		ciphertext, err := ff1.Encrypt(testVector.plaintext)
		if err != nil {
			b.Fatalf("%v", err)
		}

		plaintext, err := ff1.Decrypt(ciphertext)
		if err != nil {
			b.Fatalf("%v", err)
		}

		_ = plaintext
	}
}

// BenchmarkEncryptLong is only for benchmarking the inner for loop code bath using a very large input to make d very large, making maxJ > 1
func BenchmarkEncryptLong(b *testing.B) {
	key, _ := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")

	tweak, _ := hex.DecodeString("")

	// 16 is an arbitrary number for maxTlen
	ff1, err := NewCipher(36, 16, key, tweak)
	if err != nil {
		b.Fatalf("Unable to create cipher: %v", err)
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		ff1.Encrypt([]byte("xs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwd"))
	}
}
