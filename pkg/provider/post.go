package provider

import (
	"crypto/rsa"
	"encoding/base64"
	"reflect"

	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/signature"
	"github.com/zitadel/saml/pkg/provider/xml/md"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
	"github.com/zitadel/saml/pkg/provider/xml/xml_dsig"
)

func signaturePostProvided(
	signatureF func() *xml_dsig.SignatureType,
) func() bool {
	return func() bool {
		signatureV := signatureF()

		return signatureV != nil &&
			!reflect.DeepEqual(signatureV.SignatureValue, xml_dsig.SignatureValueType{}) &&
			signatureV.SignatureValue.Text != ""
	}
}
func signaturePostVerificationNecessary(
	idpMetadataF func() *md.IDPSSODescriptorType,
	spMetadataF func() *md.EntityDescriptorType,
	signatureF func() *xml_dsig.SignatureType,
	protocolBinding func() string,
) func() bool {
	return func() bool {
		spMeta := spMetadataF()
		idpMeta := idpMetadataF()

		return ((spMeta == nil || spMeta.SPSSODescriptor == nil || spMeta.SPSSODescriptor.AuthnRequestsSigned == "true") ||
			(idpMeta == nil || idpMeta.WantAuthnRequestsSigned == "true") ||
			signaturePostProvided(signatureF)()) &&
			protocolBinding() == PostBinding
	}
}

func verifyPostSignature(
	authRequestF func() string,
	spF func() *serviceprovider.ServiceProvider,
	errF func(error),
) func() error {
	return func() error {
		sp := spF()

		data, err := base64.StdEncoding.DecodeString(authRequestF())
		if err != nil {
			errF(err)
			return err
		}

		if err := sp.ValidatePostSignature(string(data)); err != nil {
			errF(err)
			return err
		}
		return nil
	}
}

func createPostSignature(
	samlResponse *samlp.ResponseType,
	key *rsa.PrivateKey,
	cert []byte,
	signatureAlgorithm string,
) error {
	signer, err := signature.GetSigner(cert, key, signatureAlgorithm)
	if err != nil {
		return err
	}

	asig, err := signature.Create(signer, samlResponse.Assertion)
	if err != nil {
		return err
	}

	samlResponse.Assertion.Signature = asig

	rsig, err := signature.Create(signer, samlResponse)
	if err != nil {
		return err
	}

	samlResponse.Signature = rsig
	return nil
}
