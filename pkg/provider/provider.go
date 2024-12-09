package provider

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"github.com/zitadel/saml/pkg/provider/models"
	"github.com/zitadel/saml/pkg/provider/signature"
	"github.com/zitadel/saml/pkg/provider/xml/md"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

const (
	DefaultTimeFormat       = "2006-01-02T15:04:05.999999Z"
	DefaultExpiration       = 5 * time.Minute
	PostBinding             = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	RedirectBinding         = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	DefaultMetadataEndpoint = "/metadata"
)

type Storage interface {
	EntityStorage
	AuthStorage
	IdentityProviderStorage
	UserStorage
	Health(context.Context) error
}

type Config struct {
	MetadataConfig *MetadataConfig
	IDPConfig      *IdentityProviderConfig
	Metadata       *Endpoint `yaml:"Metadata"`

	Organisation  *Organisation
	ContactPerson *ContactPerson
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

const (
	healthEndpoint    = "/healthz"
	readinessEndpoint = "/ready"
)

type Provider struct {
	storage      Storage
	httpHandler  http.Handler
	interceptors []HttpInterceptor
	insecure     bool

	metadataEndpoint  *Endpoint
	conf              *Config
	issuerFromRequest IssuerFromRequest
	identityProvider  *IdentityProvider
}

func NewProvider(
	storage Storage,
	path string,
	conf *Config,
	providerOpts ...Option,
) (*Provider, error) {
	metadataEndpoint := NewEndpoint(DefaultMetadataEndpoint)
	if conf.Metadata != nil {
		metadataEndpoint = *conf.Metadata
	}

	idp, err := NewIdentityProvider(
		metadataEndpoint,
		conf.IDPConfig,
		storage,
	)
	if err != nil {
		return nil, err
	}

	prov := &Provider{
		metadataEndpoint: &metadataEndpoint,
		storage:          storage,
		conf:             conf,
		identityProvider: idp,
	}

	for _, optFunc := range providerOpts {
		if err := optFunc(prov); err != nil {
			return nil, err
		}
	}

	issuerFromRequest, err := IssuerFromHost(path)(prov.insecure)
	if err != nil {
		return nil, err
	}
	prov.issuerFromRequest = issuerFromRequest

	prov.httpHandler = CreateRouter(prov, prov.interceptors...)

	return prov, nil
}

func NewID() string {
	return fmt.Sprintf("_%s", uuid.New())
}

func (p *Provider) IssuerFromRequest(r *http.Request) string {
	return p.issuerFromRequest(r)
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

func (p *Provider) Health(ctx context.Context) error {
	return p.storage.Health(ctx)
}

func (p *Provider) Probes() []ProbesFn {
	return []ProbesFn{
		ReadyStorage(p.storage),
	}
}

func (p *Provider) GetMetadata(ctx context.Context) (*md.EntityDescriptorType, error) {
	metadata, err := p.conf.getMetadata(ctx, p.identityProvider)
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

func getMetadataCert(ctx context.Context, storage EntityStorage) ([]byte, *rsa.PrivateKey, error) {
	certAndKey, err := storage.GetMetadataSigningKey(ctx)
	if err != nil {
		return nil, nil, err
	}

	if certAndKey.Key == nil || certAndKey.Certificate == nil {
		return nil, nil, fmt.Errorf("signer has no key")
	}

	return certAndKey.Certificate, certAndKey.Key, nil
}

type HttpInterceptor func(http.Handler) http.Handler

func CreateRouter(p *Provider, interceptors ...HttpInterceptor) *mux.Router {
	router := mux.NewRouter()

	router.Use(intercept(p.issuerFromRequest, interceptors...))
	router.HandleFunc(healthEndpoint, healthHandler)
	router.HandleFunc(readinessEndpoint, readyHandler(p.Probes()))
	router.HandleFunc(p.metadataEndpoint.Relative(), p.metadataHandle)

	if p.identityProvider != nil {
		for _, route := range p.identityProvider.GetRoutes() {
			router.Handle(route.Endpoint, route.HandleFunc)
		}
	}
	return router
}

var allowAllOrigins = func(_ string) bool {
	return true
}

// AuthCallbackURL builds the url for the redirect (with the requestID) after a successful login
func (p *Provider) AuthCallbackURL() func(context.Context, string) string {
	return func(ctx context.Context, requestID string) string {
		return p.identityProvider.endpoints.callbackEndpoint.Absolute(IssuerFromContext(ctx)) + "?id=" + requestID
	}
}

// AuthCallbackResponse returns the SAMLResponse from as successful SAMLRequest
func (p *Provider) AuthCallbackResponse(ctx context.Context, authRequest models.AuthRequestInt, response *Response) (*samlp.ResponseType, error) {
	return p.identityProvider.loginResponse(ctx, authRequest, response)
}

// AuthCallbackErrorResponse returns the SAMLResponse from as failed SAMLRequest
func (p *Provider) AuthCallbackErrorResponse(response *Response, reason, description string) *samlp.ResponseType {
	return p.identityProvider.errorResponse(response, reason, description)
}

// Timeformat return the used timeformat in messages
func (p *Provider) Timeformat() string {
	return p.identityProvider.TimeFormat
}

// Expiration return the used expiration in messages
func (p *Provider) Expiration() time.Duration {
	return p.identityProvider.Expiration
}

func intercept(i IssuerFromRequest, interceptors ...HttpInterceptor) func(handler http.Handler) http.Handler {
	cors := handlers.CORS(
		handlers.AllowCredentials(),
		handlers.AllowedHeaders([]string{"authorization", "content-type"}),
		handlers.AllowedOriginValidator(allowAllOrigins),
	)
	issuerInterceptor := NewIssuerInterceptor(i)
	return func(handler http.Handler) http.Handler {
		for i := len(interceptors) - 1; i >= 0; i-- {
			handler = interceptors[i](handler)
		}
		return cors(issuerInterceptor.Handler(handler))
	}
}

// WithAllowInsecure allows the use of http (instead of https) for issuers
// this is not recommended for production use and violates the SAML specification
func WithAllowInsecure() Option {
	return func(p *Provider) error {
		p.insecure = true
		return nil
	}
}

// WithCustomTimeFormat allows the use of a custom timeformat instead of the default
func WithCustomTimeFormat(timeFormat string) Option {
	return func(p *Provider) error {
		p.identityProvider.TimeFormat = timeFormat
		return nil
	}
}
