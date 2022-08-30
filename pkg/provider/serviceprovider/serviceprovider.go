package serviceprovider

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/beevik/etree"

	"github.com/zitadel/saml/pkg/provider/signature"
	"github.com/zitadel/saml/pkg/provider/xml"
	"github.com/zitadel/saml/pkg/provider/xml/md"
)

type Config struct {
	Metadata []byte
}

type ServiceProvider struct {
	ID              string
	Metadata        *md.EntityDescriptorType
	signerPublicKey interface{}
	defaultLoginURL string
}

func (sp *ServiceProvider) GetEntityID() string {
	return string(sp.Metadata.EntityID)
}

func (sp *ServiceProvider) LoginURL(id string) string {
	return sp.defaultLoginURL + id
}

func NewServiceProvider(id string, config *Config, defaultLoginURL string) (*ServiceProvider, error) {
	metadata, err := xml.ParseMetadataXmlIntoStruct(config.Metadata)
	if err != nil {
		return nil, err
	}

	var signerPublicKey interface{}
	certs, err := getSigningCertsFromMetadata(metadata)
	if err != nil {
		return nil, err
	}
	if len(certs) > 1 {
		return nil, fmt.Errorf("currently more than one signing certificate for service providers not supported")
	}
	if len(certs) == 1 {
		signerPublicKey = certs[0].PublicKey
	}

	return &ServiceProvider{
		ID:              id,
		Metadata:        metadata,
		signerPublicKey: signerPublicKey,
		defaultLoginURL: defaultLoginURL,
	}, nil
}

func getSigningCertsFromMetadata(metadata *md.EntityDescriptorType) ([]*x509.Certificate, error) {
	return signature.ParseCertificates(xml.GetCertsFromKeyDescriptors(metadata.SPSSODescriptor.KeyDescriptor))
}

func (sp *ServiceProvider) ValidatePostSignature(authRequest string) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes([]byte(authRequest)); err != nil {
		return err
	}

	if doc.Root() == nil {
		return fmt.Errorf("error while parsing request")
	}

	certs, err := getSigningCertsFromMetadata(sp.Metadata)
	if err != nil {
		return err
	}

	return signature.ValidatePost(certs, doc.Root())
}

func (sp *ServiceProvider) ValidateRedirectSignature(request, relayState, sigAlg, expectedSig string) error {
	if sp.signerPublicKey == nil {
		return fmt.Errorf("error can not validate signature if no certificate is present for this service provider")
	}

	elementToSign := make([]byte, 0)
	if url.QueryEscape(relayState) != "" {
		elementToSign = []byte(fmt.Sprintf("SAMLRequest=%s&RelayState=%s&SigAlg=%s", url.QueryEscape(request), url.QueryEscape(relayState), url.QueryEscape(sigAlg)))
	} else {
		elementToSign = []byte(fmt.Sprintf("SAMLRequest=%s&SigAlg=%s", url.QueryEscape(request), url.QueryEscape(sigAlg)))
	}
	signatureValue, err := base64.StdEncoding.DecodeString(expectedSig)
	if err != nil {
		return err
	}

	return signature.ValidateRedirect(sigAlg, elementToSign, signatureValue, sp.signerPublicKey)
}
