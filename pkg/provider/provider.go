package provider

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/zitadel/oidc/v2/pkg/op"
	"github.com/zitadel/saml/pkg/provider/signature"
	"github.com/zitadel/saml/pkg/provider/xml/md"
	"gopkg.in/square/go-jose.v2"
	"net/http"
)

const (
	PostBinding             = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	RedirectBinding         = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	SOAPBinding             = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
	HandlerPrefix           = "/saml"
	DefaultMetadataEndpoint = "/metadata"
)

type Storage interface {
	EntityStorage
	AuthStorage
	IdentityProviderStorage
	UserStorage
	Health(context.Context) error
}

type MetadataConfig struct {
	Path               string
	SignatureAlgorithm string
}

type Certificate struct {
	Path           string
	PrivateKeyPath string
	CaPath         string
}

type Organisation struct {
	Name        string
	DisplayName string
	URL         string
}

type ContactPerson struct {
	ContactType     md.ContactTypeType
	Company         string
	GivenName       string
	SurName         string
	EmailAddress    string
	TelephoneNumber string
}

func NewID() string {
	return fmt.Sprintf("_%s", uuid.New())
}

const (
	healthEndpoint    = "/healthz"
	readinessEndpoint = "/ready"
)

type Provider struct {
	storage      Storage
	httpHandler  http.Handler
	interceptors []HttpInterceptor
	caCert       string
	caKey        string

	metadataEndpoint  *op.Endpoint
	conf              *Config
	issuerFromRequest op.IssuerFromRequest
	IdentityProvider  *IdentityProvider
}

type Config struct {
	MetadataConfig *MetadataConfig
	IDPConfig      *IdentityProviderConfig
	Metadata       *op.Endpoint `yaml:"Metadata"`
	Insecure       bool

	Organisation  *Organisation
	ContactPerson *ContactPerson
}

func NewProvider(
	ctx context.Context,
	storage Storage,
	conf *Config,
	providerOpts ...Option,
) (*Provider, error) {
	_, _, err := getCACert(ctx, storage)
	if err != nil {
		return nil, err
	}

	metadataEndpoint := op.NewEndpoint(DefaultMetadataEndpoint)
	if conf.Metadata != nil {
		metadataEndpoint = *conf.Metadata
	}

	issuer := op.IssuerFromHost(HandlerPrefix)
	issuerFromRequest, err := issuer(conf.Insecure)
	if err != nil {
		return nil, err
	}

	idp, err := NewIdentityProvider(
		ctx,
		metadataEndpoint,
		conf.IDPConfig,
		storage,
	)
	if err != nil {
		return nil, err
	}

	prov := &Provider{
		metadataEndpoint:  &metadataEndpoint,
		storage:           storage,
		conf:              conf,
		issuerFromRequest: issuerFromRequest,
		IdentityProvider:  idp,
	}

	for _, optFunc := range providerOpts {
		if err := optFunc(prov); err != nil {
			return nil, err
		}
	}
	prov.httpHandler = CreateRouter(prov, prov.interceptors...)

	return prov, nil
}

type Option func(o *Provider) error

func WithHttpInterceptors(interceptors ...HttpInterceptor) Option {
	return func(p *Provider) error {
		p.interceptors = append(p.interceptors, interceptors...)
		return nil
	}
}

func (p *Provider) HttpHandler() http.Handler {
	return p.httpHandler
}

func (p *Provider) Storage() Storage {
	return p.storage
}

func (p *Provider) Health(ctx context.Context) error {
	return p.Storage().Health(ctx)
}

func (p *Provider) Probes() []ProbesFn {
	return []ProbesFn{
		ReadyStorage(p.Storage()),
	}
}

func (p *Provider) GetMetadata(ctx context.Context) (*md.EntityDescriptorType, error) {
	metadata, err := p.conf.getMetadata(ctx, p.IdentityProvider)
	if err != nil {
		return nil, err
	}

	cert, key, err := getMetadataCert(ctx, p.storage)
	if p.conf.MetadataConfig != nil && p.conf.MetadataConfig.SignatureAlgorithm != "" {
		signer, err := signature.GetSigner(cert, key, p.conf.MetadataConfig.SignatureAlgorithm)
		if err != nil {
			return nil, err
		}

		idpSig, err := signature.Create(signer, metadata)
		if err != nil {
			return nil, err
		}
		metadata.Signature = idpSig

	}
	return metadata, nil
}

func getCACert(ctx context.Context, storage EntityStorage) ([]byte, *rsa.PrivateKey, error) {
	certAndKey, err := storage.GetCA(ctx)
	if err != nil {
		return nil, nil, err
	}

	if certAndKey.Key.Key == nil || certAndKey.Certificate.Key == nil {
		return nil, nil, fmt.Errorf("signer has no key")
	}

	certWebKey := certAndKey.Certificate.Key.(jose.JSONWebKey)
	keyWebKey := certAndKey.Key.Key.(jose.JSONWebKey)

	return certWebKey.Key.([]byte), keyWebKey.Key.(*rsa.PrivateKey), nil
}

func getMetadataCert(ctx context.Context, storage EntityStorage) ([]byte, *rsa.PrivateKey, error) {
	certAndKey, err := storage.GetMetadataSigningKey(ctx)
	if err != nil {
		return nil, nil, err
	}

	if certAndKey.Key.Key == nil || certAndKey.Certificate.Key == nil {
		return nil, nil, fmt.Errorf("signer has no key")
	}

	certWebKey := certAndKey.Certificate.Key.(jose.JSONWebKey)
	keyWebKey := certAndKey.Key.Key.(jose.JSONWebKey)

	return certWebKey.Key.([]byte), keyWebKey.Key.(*rsa.PrivateKey), nil
}

type HttpInterceptor func(http.Handler) http.Handler

func CreateRouter(p *Provider, interceptors ...HttpInterceptor) *mux.Router {
	router := mux.NewRouter()

	router.Use(intercept(p.issuerFromRequest, interceptors...))
	router.HandleFunc(healthEndpoint, healthHandler)
	router.HandleFunc(readinessEndpoint, readyHandler(p.Probes()))
	router.HandleFunc(p.metadataEndpoint.Relative(), p.metadataHandle)

	if p.IdentityProvider != nil {
		for _, route := range p.IdentityProvider.GetRoutes() {
			router.Handle(route.Endpoint, route.HandleFunc)
		}
	}
	return router
}

var allowAllOrigins = func(_ string) bool {
	return true
}

//AuthCallbackURL builds the url for the redirect (with the requestID) after a successful login
func AuthCallbackURL(p *Provider) func(context.Context, string) string {
	return func(ctx context.Context, requestID string) string {
		return p.IdentityProvider.endpoints.CallbackEndpoint.Absolute(op.IssuerFromContext(ctx)) + "?id=" + requestID
	}
}

func intercept(i op.IssuerFromRequest, interceptors ...HttpInterceptor) func(handler http.Handler) http.Handler {
	cors := handlers.CORS(
		handlers.AllowCredentials(),
		handlers.AllowedHeaders([]string{"authorization", "content-type"}),
		handlers.AllowedOriginValidator(allowAllOrigins),
	)
	issuerInterceptor := op.NewIssuerInterceptor(i)
	return func(handler http.Handler) http.Handler {
		for i := len(interceptors) - 1; i >= 0; i-- {
			handler = interceptors[i](handler)
		}
		return cors(issuerInterceptor.Handler(handler))
	}
}
