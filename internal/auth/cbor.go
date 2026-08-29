package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// CBOR types
const (
	cborTypeUint   = 0
	cborTypeNint   = 1
	cborTypeBytes  = 2
	cborTypeText   = 3
	cborTypeArray  = 4
	cborTypeMap    = 5
	cborTypeTag    = 6
	cborTypeSimple = 7
)

// COSE Key parameter labels (RFC 8152 / RFC 9052)
const (
	coseKeyKty = 1
	coseKeyAlg = 3
	coseKeyCrv = -1
	coseKeyX   = -2
	coseKeyY   = -3
	coseKeyN   = -1
	coseKeyE   = -2
)

// COSE Key Types
const (
	coseKtyOKP = 1
	coseKtyEC2 = 2
	coseKtyRSA = 3
)

// COSE Algorithms
const (
	coseAlgES256 = -7   // ECDSA w/ SHA-256 (P-256)
	coseAlgEdDSA = -8   // EdDSA (Ed25519)
	coseAlgRS256 = -257 // RSASSA-PKCS1-v1_5 w/ SHA-256
)

// COSE Curves
const (
	coseCrvP256    = 1
	coseCrvEd25519 = 6
)

// DecodeCBOR decodes a single CBOR data item from r.
func DecodeCBOR(r io.Reader) (any, error) {
	var header [1]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	majorType := header[0] >> 5
	info := header[0] & 0x1F

	val, err := readLength(r, info)
	if err != nil {
		return nil, err
	}

	switch majorType {
	case cborTypeUint:
		return val, nil
	case cborTypeNint:
		// -1 - val
		return -1 - int64(val), nil
	case cborTypeBytes:
		b := make([]byte, val)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		return b, nil
	case cborTypeText:
		b := make([]byte, val)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		return string(b), nil
	case cborTypeArray:
		arr := make([]any, val)
		for i := uint64(0); i < val; i++ {
			elem, err := DecodeCBOR(r)
			if err != nil {
				return nil, err
			}
			arr[i] = elem
		}
		return arr, nil
	case cborTypeMap:
		m := make(map[any]any, val)
		for i := uint64(0); i < val; i++ {
			k, err := DecodeCBOR(r)
			if err != nil {
				return nil, err
			}
			v, err := DecodeCBOR(r)
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		return m, nil
	case cborTypeTag:
		// Tagged item; decode and return the inner item
		return DecodeCBOR(r)
	case cborTypeSimple:
		switch info {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		default:
			return val, nil
		}
	default:
		return nil, fmt.Errorf("unsupported CBOR major type: %d", majorType)
	}
}

func readLength(r io.Reader, info byte) (uint64, error) {
	switch {
	case info < 24:
		return uint64(info), nil
	case info == 24:
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		return uint64(b[0]), nil
	case info == 25:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint16(b[:])), nil
	case info == 26:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint32(b[:])), nil
	case info == 27:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(b[:]), nil
	default:
		return 0, fmt.Errorf("unsupported CBOR length indicator: %d", info)
	}
}

// COSEKey represents a parsed COSE public key.
type COSEKey struct {
	Kty       int64
	Alg       int64
	Crv       int64
	X         []byte
	Y         []byte
	N         []byte
	E         []byte
	PublicKey any // *ecdsa.PublicKey, *rsa.PublicKey, or ed25519.PublicKey
}

// ParseCOSEKey extracts public key parameters from a decoded CBOR map.
func ParseCOSEKey(m map[any]any) (*COSEKey, error) {
	key := &COSEKey{}

	ktyVal, ok := getMapInt(m, coseKeyKty)
	if !ok {
		return nil, errors.New("COSE key missing kty (label 1)")
	}
	key.Kty = ktyVal

	algVal, _ := getMapInt(m, coseKeyAlg)
	key.Alg = algVal

	switch key.Kty {
	case coseKtyEC2:
		crv, _ := getMapInt(m, coseKeyCrv)
		key.Crv = crv
		key.X, _ = getMapBytes(m, coseKeyX)
		key.Y, _ = getMapBytes(m, coseKeyY)

		if key.Crv != coseCrvP256 {
			return nil, fmt.Errorf("unsupported EC2 curve: %d (expected P-256)", key.Crv)
		}
		if len(key.X) != 32 || len(key.Y) != 32 {
			return nil, errors.New("invalid EC2 coordinate length")
		}

		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(key.X),
			Y:     new(big.Int).SetBytes(key.Y),
		}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("EC2 point is not on curve P-256")
		}
		key.PublicKey = pub
		if key.Alg == 0 {
			key.Alg = coseAlgES256
		}

	case coseKtyRSA:
		key.N, _ = getMapBytes(m, coseKeyN)
		key.E, _ = getMapBytes(m, coseKeyE)
		if len(key.N) == 0 || len(key.E) == 0 {
			return nil, errors.New("invalid RSA modulus or exponent")
		}

		eInt := int(new(big.Int).SetBytes(key.E).Int64())
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(key.N),
			E: eInt,
		}
		key.PublicKey = pub
		if key.Alg == 0 {
			key.Alg = coseAlgRS256
		}

	case coseKtyOKP:
		crv, _ := getMapInt(m, coseKeyCrv)
		key.Crv = crv
		key.X, _ = getMapBytes(m, coseKeyX)
		if key.Crv != coseCrvEd25519 {
			return nil, fmt.Errorf("unsupported OKP curve: %d (expected Ed25519)", key.Crv)
		}
		if len(key.X) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 public key length")
		}
		key.PublicKey = ed25519.PublicKey(key.X)
		if key.Alg == 0 {
			key.Alg = coseAlgEdDSA
		}

	default:
		return nil, fmt.Errorf("unsupported COSE key type: %d", key.Kty)
	}

	return key, nil
}

// MarshalPKIXPublicKey encodes the public key into standard PKIX ASN.1 DER bytes.
func (k *COSEKey) MarshalPKIXPublicKey() ([]byte, error) {
	if k.PublicKey == nil {
		return nil, errors.New("no public key")
	}
	return x509.MarshalPKIXPublicKey(k.PublicKey)
}

// ParsePKIXPublicKey decodes a PKIX ASN.1 DER encoded public key.
func ParsePKIXPublicKey(der []byte) (any, error) {
	return x509.ParsePKIXPublicKey(der)
}

// DecodeCOSEKeyFromBytes decodes a CBOR-encoded COSE key from raw bytes.
func DecodeCOSEKeyFromBytes(data []byte) (*COSEKey, error) {
	val, err := DecodeCBOR(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decoding CBOR COSE key: %w", err)
	}
	m, ok := val.(map[any]any)
	if !ok {
		return nil, errors.New("COSE key is not a CBOR map")
	}
	return ParseCOSEKey(m)
}

func getMapInt(m map[any]any, key int64) (int64, bool) {
	for k, v := range m {
		var kInt int64
		switch ki := k.(type) {
		case int:
			kInt = int64(ki)
		case int64:
			kInt = ki
		case uint64:
			kInt = int64(ki)
		default:
			continue
		}
		if kInt == key {
			switch vi := v.(type) {
			case int:
				return int64(vi), true
			case int64:
				return vi, true
			case uint64:
				return int64(vi), true
			}
		}
	}
	return 0, false
}

func getMapBytes(m map[any]any, key int64) ([]byte, bool) {
	for k, v := range m {
		var kInt int64
		switch ki := k.(type) {
		case int:
			kInt = int64(ki)
		case int64:
			kInt = ki
		case uint64:
			kInt = int64(ki)
		default:
			continue
		}
		if kInt == key {
			if b, ok := v.([]byte); ok {
				return b, true
			}
		}
	}
	return nil, false
}
