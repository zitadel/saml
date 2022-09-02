package key

import (
	"crypto/rsa"
)

type CertificateAndKey struct {
	Certificate []byte
	Key         *rsa.PrivateKey
}
