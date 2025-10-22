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

// Package fpeUtils provides some encoding helpers for use
// in the FF1 and FF3 format-preserving encryption packages.
package fpeUtils

import (
	"fmt"
	"reflect"
	"testing"
)

var testCodec = []struct {
	alphabet []byte
	radix    int
	input    []byte
	output   []uint8
	error    bool
}{
	{
		[]byte("0123456789abcdefghijklmnopqrstuvwxyz "),
		37,
		[]byte("hello world"),
		[]uint8{17, 14, 21, 21, 24, 36, 32, 24, 27, 21, 13},
		false,
	},
	{
		[]byte("hello world"),
		8,
		[]byte("hello world"),
		[]uint8{0, 1, 2, 2, 3, 4, 5, 3, 6, 2, 7},
		false,
	},
	{
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A},
		11,
		[]byte{0x00, 0x05, 0x0A, 0x03, 0x07},
		[]uint8{0, 5, 10, 3, 7},
		false,
	},
}

func TestCodec(t *testing.T) {
	for idx, spec := range testCodec {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			al, err := NewCodec(spec.alphabet)
			if err != nil {
				t.Fatalf("Error making codec: %s", err)
			}
			if al.Radix() != spec.radix {
				t.Fatalf("Incorrect radix %d - expected %d", al.Radix(), spec.radix)
			}

			es, err := al.Encode(spec.input)
			if err != nil {
				t.Fatalf("Unable to encode '%s' using alphabet '%s': %s", spec.input, spec.alphabet, err)
			}

			if !reflect.DeepEqual(spec.output, es) {
				t.Fatalf("Encode output incorrect: %v", es)
			}

			s, err := al.Decode(es)
			if err != nil {
				t.Fatalf("Unable to decode: %s", err)
			}

			if !reflect.DeepEqual(s, spec.input) {
				t.Fatalf("Decode error: got %v expected %v", s, spec.input)
			}
		})
	}
}

func TestEncoder(t *testing.T) {
	tests := []struct {
		alphabet []byte
		radix    int
		input    []byte
	}{
		{
			[]byte{},
			0,
			[]byte("hello world"),
		},
		{
			[]byte("helloworld"),
			7,
			[]byte("hello world"),
		},
	}

	for idx, spec := range tests {
		t.Run(fmt.Sprintf("Sample%d", idx+1), func(t *testing.T) {
			al, err := NewCodec(spec.alphabet)
			if err != nil {
				t.Fatalf("Error making codec: %s", err)
			}
			if al.Radix() != spec.radix {
				t.Fatalf("Incorrect radix %d - expected %d", al.Radix(), spec.radix)
			}

			_, err = al.Encode(spec.input)
			if err == nil {
				t.Fatalf("Encode unexpectedly succeeded: input %v, alphabet %v", spec.input, spec.alphabet)
			}
		})
	}
}

func TestLargeAlphabet(t *testing.T) {
	// Create alphabet with all 256 possible byte values
	alphabet := make([]byte, 256)
	for i := 0; i < 256; i++ {
		alphabet[i] = byte(i)
	}

	al, err := NewCodec(alphabet)
	if err != nil {
		t.Fatalf("Error making codec: %s", err)
	}
	if al.Radix() != 256 {
		t.Fatalf("Incorrect radix %d ", al.Radix())
	}

	// Test with some byte data
	testData := []byte{0x00, 0x55, 0xAA, 0xFF, 0x10, 0x20}
	nml, err := al.Encode(testData)
	if err != nil {
		t.Fatalf("Unable to encode: %s", err)
	}

	decoded, err := al.Decode(nml)
	if err != nil {
		t.Fatalf("Unable to decode: %s", err)
	}

	if !reflect.DeepEqual(decoded, testData) {
		t.Fatalf("Round-trip failed: got %v expected %v", decoded, testData)
	}
}

func TestAlphabetTooLarge(t *testing.T) {
	// Create alphabet with duplicates, should still work since duplicates are ignored
	alphabet := make([]byte, 300) // More than 256 bytes
	for i := 0; i < 300; i++ {
		alphabet[i] = byte(i % 256) // This creates duplicates
	}

	// This should work since duplicates are ignored
	al, err := NewCodec(alphabet)
	if err != nil {
		t.Fatalf("Error making codec: %s", err)
	}
	if al.Radix() != 256 {
		t.Fatalf("Incorrect radix %d - expected 256", al.Radix())
	}
}

func TestMaxAlphabetExceeded(t *testing.T) {
	// Create a scenario where we would exceed 256 unique bytes
	// This isn't actually possible with byte slices since there are only 256 possible byte values
	// But we can test that our implementation correctly handles the 255 position overflow

	// Create alphabet with all unique bytes
	alphabet := make([]byte, 256)
	for i := 0; i < 256; i++ {
		alphabet[i] = byte(i)
	}

	al, err := NewCodec(alphabet)
	if err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}
	if al.Radix() != 256 {
		t.Fatalf("Incorrect radix %d - expected 256", al.Radix())
	}
}
