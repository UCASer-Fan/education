
package gm

import (
	"crypto/sha256"
	"errors"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
)

//定义国密 SM4 结构体，实现 bccsp Key 的接口
type gmsm4PrivateKey struct {
	privKey    []byte
	exportable bool
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *gmsm4PrivateKey) Bytes() (raw []byte, err error) {
	if k.exportable {
		return k.privKey, nil
	}

	return nil, errors.New("Not supported")
}

// SKI returns the subject key identifier of this key.
func (k *gmsm4PrivateKey) SKI() (ski []byte) {
	hash := sha256.New()
	//hash := NewSM3()
	hash.Write([]byte{0x01})
	hash.Write(k.privKey)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *gmsm4PrivateKey) Symmetric() bool {
	return true
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *gmsm4PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *gmsm4PrivateKey) PublicKey() (bccsp.Key, error) {
	return nil, errors.New("Cannot call this method on a symmetric key")
}
