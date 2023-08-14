package provider

import (
	"context"

	"github.com/zitadel/saml/pkg/provider/key"
	"github.com/zitadel/saml/pkg/provider/models"
	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

type EntityStorage interface {
	GetCA(context.Context) (*key.CertificateAndKey, error)
	GetMetadataSigningKey(context.Context) (*key.CertificateAndKey, error)
}

type IdentityProviderStorage interface {
	GetEntityByID(ctx context.Context, entityID string) (*serviceprovider.ServiceProvider, error)
	GetEntityIDByAppID(ctx context.Context, entityID string) (string, error)
	GetResponseSigningKey(context.Context) (*key.CertificateAndKey, error)
}

type AuthStorage interface {
	CreateAuthRequest(context.Context, *samlp.AuthnRequestType, string, string, string, string) (models.AuthRequestInt, error)
	AuthRequestByID(context.Context, string) (models.AuthRequestInt, error)
}

type UserStorage interface {
	SetUserinfoWithUserID(ctx context.Context, applicationID string, userinfo models.AttributeSetter, userID string, attributes []int) (err error)
	SetUserinfoWithLoginName(ctx context.Context, userinfo models.AttributeSetter, loginName string, attributes []int) (err error)
}
