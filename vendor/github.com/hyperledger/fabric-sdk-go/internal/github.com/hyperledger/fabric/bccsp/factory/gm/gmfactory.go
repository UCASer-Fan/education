package gm

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/factory/sw"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/gm"
	"github.com/pkg/errors"
)

const (
	// SoftwareBasedFactoryName is the name of the factory of the software-based BCCSP implementation
	GuomiBasedFactoryName = "GM"
)

// GMFactory is the factory of the Gomi-based BCCSP.
type GMFactory struct{}

// Name returns the name of this factory
func (f *GMFactory) Name() string {
	return GuomiBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *GMFactory) Get(gmOpts *sw.SwOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if gmOpts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	var ks bccsp.KeyStore
	switch {
	case gmOpts.Ephemeral:
		ks = gm.NewDummyKeyStore()
	case gmOpts.FileKeystore != nil:
		fks, err := gm.NewFileBasedKeyStore(nil, gmOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to initialize software key store")
		}
		ks = fks
	default:
		// Default to ephemeral key store
		ks = gm.NewDummyKeyStore()
	}

	return gm.New(gmOpts.SecLevel, "GMSM3", ks)
}
