package provider

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml/md"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
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
	ValidUntil    time.Duration
	CacheDuration string
	ErrorURL      string
}

type IdentityProviderConfig struct {
	MetadataIDPConfig *MetadataIDPConfig

	PostTemplate   *template.Template
	LogoutTemplate *template.Template

	SignatureAlgorithm  string
	DigestAlgorithm     string
	EncryptionAlgorithm string

	WantAuthRequestsSigned string
	Insecure               bool

	Endpoints *EndpointConfig `yaml:"Endpoints"`
}

type EndpointConfig struct {
	Certificate  *Endpoint `yaml:"Certificate"`
	Callback     *Endpoint `yaml:"Callback"`
	SingleSignOn *Endpoint `yaml:"SingleSignOn"`
	SingleLogOut *Endpoint `yaml:"SingleLogOut"`
	Attribute    *Endpoint `yaml:"Attribute"`
}

type IdentityProvider struct {
	conf           *IdentityProviderConfig
	storage        IDPStorage
	postTemplate   *template.Template
	logoutTemplate *template.Template

	metadataEndpoint *Endpoint
	endpoints        *Endpoints

	TimeFormat string
	Expiration time.Duration
}

type Endpoints struct {
	certificateEndpoint  Endpoint
	callbackEndpoint     Endpoint
	singleSignOnEndpoint Endpoint
	singleLogoutEndpoint Endpoint
	attributeEndpoint    Endpoint
}

func NewIdentityProvider(metadata Endpoint, conf *IdentityProviderConfig, storage IDPStorage) (_ *IdentityProvider, err error) {
	idp := &IdentityProvider{
		storage:          storage,
		metadataEndpoint: &metadata,
		conf:             conf,
		postTemplate:     conf.PostTemplate,
		logoutTemplate:   conf.LogoutTemplate,
		endpoints:        endpointConfigToEndpoints(conf.Endpoints),
		TimeFormat:       DefaultTimeFormat,
		Expiration:       DefaultExpiration,
	}

	if conf.PostTemplate == nil {
		idp.postTemplate, err = template.New("post").Parse(postTemplate)
		if err != nil {
			return nil, err
		}
	}

	if conf.LogoutTemplate == nil {
		idp.logoutTemplate, err = template.New("logout").Parse(logoutTemplate)
		if err != nil {
			return nil, err
		}
	}

	if conf.MetadataIDPConfig == nil {
		conf.MetadataIDPConfig = &MetadataIDPConfig{}
	}
	if conf.MetadataIDPConfig.ValidUntil == 0 {
		conf.MetadataIDPConfig.ValidUntil = DefaultValidUntil
	}

	return idp, nil
}

func (p *IdentityProvider) GetEntityID(ctx context.Context) string {
	return p.metadataEndpoint.Absolute(IssuerFromContext(ctx))
}

func endpointConfigToEndpoints(conf *EndpointConfig) *Endpoints {
	endpoints := &Endpoints{
		certificateEndpoint:  NewEndpoint(DefaultCertificateEndpoint),
		callbackEndpoint:     NewEndpoint(DefaultCallbackEndpoint),
		singleSignOnEndpoint: NewEndpoint(DefaultSingleSignOnEndpoint),
		singleLogoutEndpoint: NewEndpoint(DefaultSingleLogOutEndpoint),
		attributeEndpoint:    NewEndpoint(DefaultAttributeEndpoint),
	}

	if conf != nil {
		if conf.Certificate != nil {
			endpoints.certificateEndpoint = *conf.Certificate
		}

		if conf.Callback != nil {
			endpoints.callbackEndpoint = *conf.Callback
		}

		if conf.SingleSignOn != nil {
			endpoints.singleSignOnEndpoint = *conf.SingleSignOn
		}

		if conf.SingleLogOut != nil {
			endpoints.singleLogoutEndpoint = *conf.SingleLogOut
		}

		if conf.Attribute != nil {
			endpoints.attributeEndpoint = *conf.Attribute
		}
	}
	return endpoints
}

func (p *IdentityProvider) GetMetadata(ctx context.Context) (*md.IDPSSODescriptorType, *md.AttributeAuthorityDescriptorType, error) {
	cert, _, err := getResponseCert(ctx, p.storage)
	if err != nil {
		return nil, nil, err
	}

	metadata, aaMetadata := p.conf.getMetadata(p.GetEntityID(ctx), IssuerFromContext(ctx), cert, p.TimeFormat)
	return metadata, aaMetadata, nil
}

type Route struct {
	Endpoint   string
	HandleFunc http.HandlerFunc
}

func (p *IdentityProvider) GetRoutes() []*Route {
	return []*Route{
		{p.endpoints.certificateEndpoint.Relative(), p.certificateHandleFunc},
		{p.endpoints.callbackEndpoint.Relative(), p.callbackHandleFunc},
		{p.endpoints.singleSignOnEndpoint.Relative(), p.ssoHandleFunc},
		{p.endpoints.singleLogoutEndpoint.Relative(), p.logoutHandleFunc},
		{p.endpoints.attributeEndpoint.Relative(), p.attributeQueryHandleFunc},
	}
}

func (p *IdentityProvider) GetServiceProvider(ctx context.Context, entityID string) (*serviceprovider.ServiceProvider, error) {
	return p.storage.GetEntityByID(ctx, entityID)
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
		certAndKey.Key == nil ||
		certAndKey.Certificate == nil {
		return nil, nil, fmt.Errorf("signer has no key")
	}

	if len(certAndKey.Certificate) == 0 {
		return nil, nil, fmt.Errorf("failed to parse certificate")
	}

	if certAndKey.Key == nil || reflect.DeepEqual(certAndKey.Key, rsa.PrivateKey{}) {
		return nil, nil, fmt.Errorf("failed to parse key")
	}

	return certAndKey.Certificate, certAndKey.Key, nil
}

func (i *IdentityProvider) certificateHandleFunc(w http.ResponseWriter, r *http.Request) {
	cert, _, err := getResponseCert(r.Context(), i.storage)
	if err != nil {
		http.Error(w, fmt.Errorf("failed to read certificate: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	certPem := new(bytes.Buffer)
	if err := pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
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
