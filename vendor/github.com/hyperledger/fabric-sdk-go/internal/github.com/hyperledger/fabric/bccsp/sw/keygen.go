
package gm

import (
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/ldstyle8/gmsm/sm2"
)

//定义国密SM2 keygen 结构体，实现 KeyGenerator 接口
type gmsm2KeyGenerator struct {
}

func (gm *gmsm2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	//调用 SM2的注册证书方法
	privKey, err := sm2.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating GMSM2 key  [%s]", err)
	}

	return &gmsm2PrivateKey{privKey}, nil
}

//定义国密SM4 keygen 结构体，实现 KeyGenerator 接口
type gmsm4KeyGenerator struct {
	length int
}

func (gm *gmsm4KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	lowLevelKey, err := GetRandomBytes(int(gm.length))
	if err != nil {
		return nil, fmt.Errorf("Failed generating GMSM4 %d key [%s]", gm.length, err)
	}

	return &gmsm4PrivateKey{lowLevelKey, false}, nil
}
