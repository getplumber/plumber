package utils

import (
	"hash/fnv"
)

// GenerateFNVHash generates a 64-bit FNV-1a hash from the input bytes
func GenerateFNVHash(data []byte) uint64 {
	h := fnv.New64a()
	h.Write(data)
	return h.Sum64()
}
