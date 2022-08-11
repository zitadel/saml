package signature

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"

	"github.com/amdonov/xmlsig"
	dsig "github.com/russellhaering/goxmldsig"
)

func ParseCertificates(certStrs []string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	regex := regexp.MustCompile(`\s+`)
	for _, certStr := range certStrs {
		certStr = regex.ReplaceAllString(certStr, "")
		certStr = strings.TrimPrefix(strings.TrimSuffix(certStr, "-----ENDCERTIFICATE-----"), "-----BEGINCERTIFICATE-----")
		certBytes, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM block containing the public key")
		}
		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: " + err.Error())
		}
		certs = append(certs, parsedCert)
	}

	return certs, nil
}

func ParseTlsKeyPair(cert []byte, key *rsa.PrivateKey) (tls.Certificate, error) {
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		},
	)

	keyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	return tls.X509KeyPair(certPem, keyPem)
}

func GetSigningContextAndSigner(
	cert []byte,
	key *rsa.PrivateKey,
	signatureAlgorithm string,
) (*dsig.SigningContext, xmlsig.Signer, error) {
	if err := isValidSignatureAlgorithm(signatureAlgorithm); err != nil {
		return nil, nil, err
	}

	tlsCert, err := ParseTlsKeyPair(cert, key)
	if err != nil {
		return nil, nil, err
	}

	signingContext, err := GetSigningContext(tlsCert, signatureAlgorithm)
	if err != nil {
		return nil, nil, err
	}

	signer, err := xmlsig.NewSignerWithOptions(tlsCert, xmlsig.SignerOptions{
		SignatureAlgorithm: signingContext.GetSignatureMethodIdentifier(),
		DigestAlgorithm:    signingContext.GetDigestAlgorithmIdentifier(),
	})
	if err != nil {
		return nil, nil, err
	}

	return signingContext, signer, nil
}

func GetSigner(
	cert []byte,
	key *rsa.PrivateKey,
	signatureAlgorithm string,
) (xmlsig.Signer, error) {
	if err := isValidSignatureAlgorithm(signatureAlgorithm); err != nil {
		return nil, err
	}

	tlsCert, err := ParseTlsKeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	signer, err := xmlsig.NewSignerWithOptions(tlsCert, xmlsig.SignerOptions{
		SignatureAlgorithm: signatureAlgorithm,
		DigestAlgorithm:    "http://www.w3.org/2001/04/xmlenc#sha256",
	})
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func GetSigningContext(tlsCert tls.Certificate, signatureAlgorithm string) (*dsig.SigningContext, error) {
	signingContext := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tlsCert))
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signingContext.SetSignatureMethod(signatureAlgorithm); err != nil {
		return nil, err
	}
	return signingContext, nil
}

func isValidSignatureAlgorithm(alg string) error {
	switch alg {
	case dsig.RSASHA1SignatureMethod,
		dsig.RSASHA256SignatureMethod,
		dsig.RSASHA512SignatureMethod:
		return nil
	default:
		return fmt.Errorf("invalid signing method %s", alg)
	}
}
