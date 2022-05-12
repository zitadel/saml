package provider

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type valueKey int

var (
	issuer valueKey = 1
)

type IssuerInterceptor struct {
	issuerFromRequest IssuerFromRequest
}

//NewIssuerInterceptor will set the issuer into the context
//by the provided IssuerFromRequest (e.g. returned from StaticIssuer or IssuerFromHost)
func NewIssuerInterceptor(issuerFromRequest IssuerFromRequest) *IssuerInterceptor {
	return &IssuerInterceptor{
		issuerFromRequest: issuerFromRequest,
	}
}

func (i *IssuerInterceptor) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i.setIssuerCtx(w, r, next)
	})
}

func (i *IssuerInterceptor) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		i.setIssuerCtx(w, r, next)
	}
}

//IssuerFromContext reads the issuer from the context (set by an IssuerInterceptor)
//it will return an empty string if not found
func IssuerFromContext(ctx context.Context) string {
	ctxIssuer, _ := ctx.Value(issuer).(string)
	return ctxIssuer
}

func (i *IssuerInterceptor) setIssuerCtx(w http.ResponseWriter, r *http.Request, next http.Handler) {
	ctx := context.WithValue(r.Context(), issuer, i.issuerFromRequest(r))
	r = r.WithContext(ctx)
	next.ServeHTTP(w, r)
}

var (
	ErrInvalidIssuerPath        = errors.New("no fragments or query allowed for issuer")
	ErrInvalidIssuerNoIssuer    = errors.New("missing issuer")
	ErrInvalidIssuerURL         = errors.New("invalid url for issuer")
	ErrInvalidIssuerMissingHost = errors.New("host for issuer missing")
	ErrInvalidIssuerHTTPS       = errors.New("scheme for issuer must be `https`")
)

type IssuerFromRequest func(r *http.Request) string

func IssuerFromHost(path string) func(bool) (IssuerFromRequest, error) {
	return func(allowInsecure bool) (IssuerFromRequest, error) {
		issuerPath, err := url.Parse(path)
		if err != nil {
			return nil, ErrInvalidIssuerURL
		}
		if err := ValidateIssuerPath(issuerPath); err != nil {
			return nil, err
		}
		return func(r *http.Request) string {
			return dynamicIssuer(r.Host, path, allowInsecure)
		}, nil
	}
}

func StaticIssuer(issuer string) func(bool) (IssuerFromRequest, error) {
	return func(allowInsecure bool) (IssuerFromRequest, error) {
		if err := ValidateIssuer(issuer, allowInsecure); err != nil {
			return nil, err
		}
		return func(_ *http.Request) string {
			return issuer
		}, nil
	}
}

func ValidateIssuer(issuer string, allowInsecure bool) error {
	if issuer == "" {
		return ErrInvalidIssuerNoIssuer
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return ErrInvalidIssuerURL
	}
	if u.Host == "" {
		return ErrInvalidIssuerMissingHost
	}
	if u.Scheme != "https" {
		if !devLocalAllowed(u, allowInsecure) {
			return ErrInvalidIssuerHTTPS
		}
	}
	return ValidateIssuerPath(u)
}

func ValidateIssuerPath(issuer *url.URL) error {
	if issuer.Fragment != "" || len(issuer.Query()) > 0 {
		return ErrInvalidIssuerPath
	}
	return nil
}

func devLocalAllowed(url *url.URL, allowInsecure bool) bool {
	if !allowInsecure {
		return false
	}
	return url.Scheme == "http"
}

func dynamicIssuer(issuer, path string, allowInsecure bool) string {
	schema := "https"
	if allowInsecure {
		schema = "http"
	}
	if len(path) > 0 && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return schema + "://" + issuer + path
}
