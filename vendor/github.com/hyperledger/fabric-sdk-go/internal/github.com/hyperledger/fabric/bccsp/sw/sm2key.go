
package gm

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/ldstyle8/gmsm/sm2"
)

type gmsm2PrivateKey struct {
	privKey *sm2.PrivateKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *gmsm2PrivateKey) Bytes() (raw []byte, err error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *gmsm2PrivateKey) SKI() (ski []byte) {
	if k.privKey == nil {
		return nil
	}

	//Marshall the public key
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *gmsm2PrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *gmsm2PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *gmsm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &gmsm2PublicKey{&k.privKey.PublicKey}, nil
}

type gmsm2PublicKey struct {
	pubKey *sm2.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *gmsm2PublicKey) Bytes() (raw []byte, err error) {
	raw, err = sm2.MarshalSm2PublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *gmsm2PublicKey) SKI() (ski []byte) {
	if k.pubKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *gmsm2PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *gmsm2PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *gmsm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
