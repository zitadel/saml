package provider

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"github.com/zitadel/oidc/v2/pkg/op"
	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml/md"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
	"gopkg.in/square/go-jose.v2"
	"io"
	"net/http"
	"reflect"
	"text/template"
)

const (
	DefaultCertificateEndpoint  = "certificate"
	DefaultCallbackEndpoint     = "login"
	DefaultSingleSignOnEndpoint = "SSO"
	DefaultSingleLogOutEndpoint = "SLO"
	DefaultAttributeEndpoint    = "attribute"
)

type IDPStorage interface {
	AuthStorage
	IdentityProviderStorage
	UserStorage
	Health(context.Context) error
}

type MetadataIDPConfig struct {
	ValidUntil    string
	CacheDuration string
	ErrorURL      string
}

type IdentityProviderConfig struct {
	MetadataIDPConfig *MetadataIDPConfig

	SignatureAlgorithm  string
	DigestAlgorithm     string
	EncryptionAlgorithm string

	WantAuthRequestsSigned string
	Insecure               bool

	Endpoints *EndpointConfig `yaml:"Endpoints"`
}

type EndpointConfig struct {
	Certificate  *op.Endpoint `yaml:"Certificate"`
	Callback     *op.Endpoint `yaml:"Callback"`
	SingleSignOn *op.Endpoint `yaml:"SingleSignOn"`
	SingleLogOut *op.Endpoint `yaml:"SingleLogOut"`
	Attribute    *op.Endpoint `yaml:"Attribute"`
}

type IdentityProvider struct {
	conf           *IdentityProviderConfig
	storage        IDPStorage
	postTemplate   *template.Template
	logoutTemplate *template.Template

	metadataEndpoint *op.Endpoint

	metadata   *md.IDPSSODescriptorType
	aaMetadata *md.AttributeAuthorityDescriptorType

	endpoints *Endpoints

	serviceProviders []*serviceprovider.ServiceProvider
}

type Endpoints struct {
	CertificateEndpoint  op.Endpoint
	CallbackEndpoint     op.Endpoint
	SingleSignOnEndpoint op.Endpoint
	SingleLogoutEndpoint op.Endpoint
	AttributeEndpoint    op.Endpoint
}

func NewIdentityProvider(ctx context.Context, metadata op.Endpoint, conf *IdentityProviderConfig, storage IDPStorage) (*IdentityProvider, error) {
	postTemplate, err := template.New("post").Parse(postTemplate)
	if err != nil {
		return nil, err
	}

	logoutTemplate, err := template.New("logout").Parse(logoutTemplate)
	if err != nil {
		return nil, err
	}

	idp := &IdentityProvider{
		storage:          storage,
		metadataEndpoint: &metadata,
		conf:             conf,
		postTemplate:     postTemplate,
		logoutTemplate:   logoutTemplate,
		endpoints:        endpointConfigToEndpoints(conf.Endpoints),
	}

	return idp, nil
}

func (p *IdentityProvider) GetEntityID(ctx context.Context) string {
	return p.metadataEndpoint.Absolute(op.IssuerFromContext(ctx))
}

func endpointConfigToEndpoints(conf *EndpointConfig) *Endpoints {
	endpoints := &Endpoints{
		CertificateEndpoint:  op.NewEndpoint(DefaultCertificateEndpoint),
		CallbackEndpoint:     op.NewEndpoint(DefaultCallbackEndpoint),
		SingleSignOnEndpoint: op.NewEndpoint(DefaultSingleSignOnEndpoint),
		SingleLogoutEndpoint: op.NewEndpoint(DefaultSingleLogOutEndpoint),
		AttributeEndpoint:    op.NewEndpoint(DefaultAttributeEndpoint),
	}

	if conf != nil {
		if conf.Certificate != nil {
			endpoints.CertificateEndpoint = *conf.Certificate
		}

		if conf.Callback != nil {
			endpoints.CallbackEndpoint = *conf.Callback
		}

		if conf.SingleSignOn != nil {
			endpoints.SingleSignOnEndpoint = *conf.SingleSignOn
		}

		if conf.SingleLogOut != nil {
			endpoints.SingleLogoutEndpoint = *conf.SingleLogOut
		}

		if conf.Attribute != nil {
			endpoints.AttributeEndpoint = *conf.Attribute
		}
	}
	return endpoints
}

type Route struct {
	Endpoint   string
	HandleFunc http.HandlerFunc
}

func (p *IdentityProvider) GetMetadata(ctx context.Context) (*md.IDPSSODescriptorType, *md.AttributeAuthorityDescriptorType, error) {
	cert, _, err := getResponseCert(ctx, p.storage)
	if err != nil {
		return nil, nil, err
	}

	metadata, aaMetadata := p.conf.getMetadata(ctx, p.GetEntityID(ctx), cert)
	return metadata, aaMetadata, nil
}

func (p *IdentityProvider) GetRoutes() []*Route {
	return []*Route{
		{p.endpoints.CertificateEndpoint.Relative(), p.certificateHandleFunc},
		{p.endpoints.CallbackEndpoint.Relative(), p.callbackHandleFunc},
		{p.endpoints.SingleSignOnEndpoint.Relative(), p.ssoHandleFunc},
		{p.endpoints.SingleLogoutEndpoint.Relative(), p.logoutHandleFunc},
		{p.endpoints.AttributeEndpoint.Relative(), p.attributeQueryHandleFunc},
	}
}

func (p *IdentityProvider) GetServiceProvider(ctx context.Context, entityID string) (*serviceprovider.ServiceProvider, error) {
	index := 0
	found := false
	for i, sp := range p.serviceProviders {
		if sp.GetEntityID() == entityID {
			found = true
			index = i
			break
		}
	}
	if found == true {
		return p.serviceProviders[index], nil
	}

	sp, err := p.storage.GetEntityByID(ctx, entityID)
	if err != nil {
		return nil, err
	}
	if sp != nil {
		p.serviceProviders = append(p.serviceProviders, sp)
	}
	return sp, nil
}

func (p *IdentityProvider) DeleteServiceProvider(entityID string) error {
	index := 0
	found := false
	for i, sp := range p.serviceProviders {
		if sp.GetEntityID() == entityID {
			found = true
			index = i
			break
		}
	}
	if found == true {
		p.serviceProviders = append(p.serviceProviders[:index], p.serviceProviders[index+1:]...)
	}
	return nil
}

func verifyRequestDestinationOfAuthRequest(metadata *md.IDPSSODescriptorType, request *samlp.AuthnRequestType) error {
	// google provides no destination in their requests
	if request.Destination != "" {
		foundEndpoint := false
		for _, sso := range metadata.SingleSignOnService {
			if request.Destination == sso.Location {
				foundEndpoint = true
				break
			}
		}
		if !foundEndpoint {
			return fmt.Errorf("destination of request is unknown")
		}
	}
	return nil
}

func verifyRequestDestinationOfAttrQuery(metadata *md.IDPSSODescriptorType, request *samlp.AttributeQueryType) error {
	// google provides no destination in their requests
	if request.Destination != "" {
		foundEndpoint := false
		for _, sso := range metadata.SingleSignOnService {
			if request.Destination == sso.Location {
				foundEndpoint = true
				break
			}
		}
		if !foundEndpoint {
			return fmt.Errorf("destination of request is unknown")
		}
	}
	return nil
}

func getResponseCert(ctx context.Context, storage IdentityProviderStorage) ([]byte, *rsa.PrivateKey, error) {
	certAndKey, err := storage.GetResponseSigningKey(ctx)
	if err != nil {
		return nil, nil, err
	}

	if certAndKey == nil ||
		certAndKey.Key == nil || certAndKey.Key.Key == nil ||
		certAndKey.Certificate == nil || certAndKey.Certificate.Key == nil {
		return nil, nil, fmt.Errorf("signer has no key")
	}

	certWebKey := certAndKey.Certificate.Key.(jose.JSONWebKey)
	if certWebKey.Key == nil {
		return nil, nil, fmt.Errorf("certificate is nil")
	}
	cert, ok := certWebKey.Key.([]byte)
	if !ok || cert == nil || len(cert) == 0 {
		return nil, nil, fmt.Errorf("failed to parse certificate")
	}

	keyWebKey := certAndKey.Key.Key.(jose.JSONWebKey)
	if keyWebKey.Key == nil {
		return nil, nil, fmt.Errorf("key is nil")
	}
	key, ok := keyWebKey.Key.(*rsa.PrivateKey)
	if !ok || key == nil || reflect.DeepEqual(key, rsa.PrivateKey{}) {
		return nil, nil, fmt.Errorf("failed to parse key")
	}

	return cert, key, nil
}

func (i *IdentityProvider) certificateHandleFunc(w http.ResponseWriter, r *http.Request) {
	cert, _, err := getResponseCert(r.Context(), i.storage)
	if err != nil {
		http.Error(w, fmt.Errorf("failed to read certificate: %w", err).Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf(op.IssuerFromContext(r.Context()))

	certPem := new(bytes.Buffer)
	if err := pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte(cert),
	}); err != nil {
		http.Error(w, fmt.Errorf("failed to pem encode certificate: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=idp.crt")
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	_, err = io.Copy(w, certPem)
	if err != nil {
		http.Error(w, fmt.Errorf("failed to response with certificate: %w", err).Error(), http.StatusInternalServerError)
		return
	}
}
