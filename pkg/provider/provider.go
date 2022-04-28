package provider

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/amdonov/xmlsig"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/pkg/op"
	"github.com/zitadel/saml/pkg/provider/key"
	"github.com/zitadel/saml/pkg/provider/signature"
	"github.com/zitadel/saml/pkg/provider/xml/md"
	"gopkg.in/square/go-jose.v2"
	"net/http"
)

const (
	PostBinding     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	RedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	SOAPBinding     = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
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
	URL                string
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

	MetadataEndpoint *op.Endpoint
	Metadata         *md.EntityDescriptorType
	signingContext   *dsig.SigningContext
	signer           xmlsig.Signer

	IdentityProvider *IdentityProvider
}

type Config struct {
	MetadataConfig *MetadataConfig
	IDPConfig      *IdentityProviderConfig

	Organisation  *Organisation
	ContactPerson *ContactPerson
}

func NewProvider(
	ctx context.Context,
	storage Storage,
	conf *Config,
	providerOpts ...Option,
) (*Provider, error) {
	getCACert(ctx, storage)
	cert, key := getMetadataCert(ctx, storage)
	signingContext, signer, err := signature.GetSigningContextAndSigner(cert, key, conf.MetadataConfig.SignatureAlgorithm)

	metadata := op.NewEndpointWithURL(conf.MetadataConfig.Path, conf.MetadataConfig.URL)

	idp, err := NewIdentityProvider(
		&metadata,
		conf.IDPConfig,
		storage,
	)
	if err != nil {
		return nil, err
	}

	prov := &Provider{
		MetadataEndpoint: &metadata,
		Metadata:         conf.getMetadata(idp),
		signingContext:   signingContext,
		signer:           signer,
		storage:          storage,
		IdentityProvider: idp,
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
func getCACert(ctx context.Context, storage Storage) ([]byte, *rsa.PrivateKey) {
	certAndKeyCh := make(chan key.CertificateAndKey)
	go storage.GetCA(ctx, certAndKeyCh)
	for {
		select {
		case <-ctx.Done():
			//TODO
		case certAndKey := <-certAndKeyCh:
			if certAndKey.Key.Key == nil || certAndKey.Certificate.Key == nil {
				logging.Log("OP-DAvt4").Warn("signer has no key")
				continue
			}
			certWebKey := certAndKey.Certificate.Key.(jose.JSONWebKey)
			keyWebKey := certAndKey.Key.Key.(jose.JSONWebKey)

			return certWebKey.Key.([]byte), keyWebKey.Key.(*rsa.PrivateKey)
		}
	}
}

func getMetadataCert(ctx context.Context, storage Storage) ([]byte, *rsa.PrivateKey) {
	certAndKeyCh := make(chan key.CertificateAndKey)
	go storage.GetMetadataSigningKey(ctx, certAndKeyCh)

	for {
		select {
		case <-ctx.Done():
			//TODO
		case certAndKey := <-certAndKeyCh:
			if certAndKey.Key.Key == nil || certAndKey.Certificate.Key == nil {
				logging.Log("OP-DAvt4").Warn("signer has no key")
				continue
			}
			certWebKey := certAndKey.Certificate.Key.(jose.JSONWebKey)
			keyWebKey := certAndKey.Key.Key.(jose.JSONWebKey)

			return certWebKey.Key.([]byte), keyWebKey.Key.(*rsa.PrivateKey)
		}
	}
}

type HttpInterceptor func(http.Handler) http.Handler

func CreateRouter(p *Provider, interceptors ...HttpInterceptor) *mux.Router {
	intercept := buildInterceptor(interceptors...)
	router := mux.NewRouter()
	router.Use(handlers.CORS(
		handlers.AllowCredentials(),
		handlers.AllowedHeaders([]string{"authorization", "content-type"}),
		handlers.AllowedOriginValidator(allowAllOrigins),
	))
	router.HandleFunc(healthEndpoint, healthHandler)
	router.HandleFunc(readinessEndpoint, readyHandler(p.Probes()))
	router.HandleFunc(p.MetadataEndpoint.Relative(), p.metadataHandle)

	if p.IdentityProvider != nil {
		for _, route := range p.IdentityProvider.GetRoutes() {
			router.Handle(route.Endpoint, intercept(route.HandleFunc))
		}
	}
	return router
}

var allowAllOrigins = func(_ string) bool {
	return true
}

func buildInterceptor(interceptors ...HttpInterceptor) func(http.HandlerFunc) http.Handler {
	return func(handlerFunc http.HandlerFunc) http.Handler {
		handler := handlerFuncToHandler(handlerFunc)
		for i := len(interceptors) - 1; i >= 0; i-- {
			handler = interceptors[i](handler)
		}
		return handler
	}
}

func handlerFuncToHandler(handlerFunc http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerFunc(w, r)
	})
}
