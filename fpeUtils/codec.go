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
)

// Codec supports the conversion of an arbitrary byte alphabet into ordinal
// values from 0 to length of alphabet-1.
// Element 'btu' (byte-to-uint8) supports the mapping from bytes to ordinal values.
// Element 'utb' (uint8-to-byte) supports the mapping from ordinal values to bytes.
// Element 'found' tracks which bytes are in the alphabet.
type Codec struct {
	btu   [256]uint8 // maps each byte value to its position in alphabet
	utb   []byte     // maps ordinal position to byte value
	found [256]bool  // tracks which bytes are in the alphabet
}

// NewCodec builds a Codec from the set of unique bytes in the alphabet.
// The alphabet contains arbitrary bytes from 0x00 to 0xFF.
// It is an error to try to construct a codec from an alphabet with more than 256 bytes.
func NewCodec(alphabet []byte) (Codec, error) {
	var ret Codec

	ret.utb = make([]byte, 0, len(alphabet))

	var pos uint8
	for _, b := range alphabet {
		// duplicates are tolerated, but ignored.
		if !ret.found[b] { // not yet seen
			if len(ret.utb) >= 256 {
				return ret, fmt.Errorf("alphabet must contain no more than 256 unique bytes")
			}
			ret.utb = append(ret.utb, b)
			ret.btu[b] = pos
			ret.found[b] = true
			pos++
		}
	}

	return ret, nil
}

// Radix returns the size of the alphabet supported by the Codec.
func (a *Codec) Radix() int {
	return len(a.utb)
}

// Encode the supplied byte slice as an array of ordinal values giving the
// position of each byte in the alphabet.
// It is an error for the supplied byte slice to contain bytes that are not
// in the alphabet.
func (a *Codec) Encode(data []byte) ([]uint8, error) {
	n := len(data)
	c := n
	if n%2 == 1 {
		// ensure the numeral array has even-sized capacity for FF3
		c++
	}
	ret := make([]uint8, n, c)

	for i, b := range data {
		if !a.found[b] { // not found in alphabet
			return ret, fmt.Errorf("byte at position %d is not in alphabet: 0x%02x", i, b)
		}
		ret[i] = a.btu[b]
	}
	return ret, nil
}

// Decode constructs a byte slice from an array of ordinal values where each
// value specifies the position of the byte in the alphabet.
// It is an error for the array to contain values outside the boundary of the
// alphabet.
func (a *Codec) Decode(n []uint8) ([]byte, error) {
	ret := make([]byte, len(n))

	for i, v := range n {
		if int(v) > len(a.utb)-1 {
			return nil, fmt.Errorf("numeral at position %d out of range: %d not in [0..%d]", i, v, len(a.utb)-1)
		}
		ret[i] = a.utb[v]
	}
	return ret, nil
}
