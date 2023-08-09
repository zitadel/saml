package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zitadel/saml/pkg/provider/xml/saml"
)

func TestSSO_Attributes(t *testing.T) {
	type args struct {
		email            string
		fullName         string
		givenName        string
		surname          string
		userID           string
		username         string
		customAttributes map[string]*CustomAttribute
	}
	tests := []struct {
		name string
		args args
		res  []*saml.AttributeType
	}{
		{
			"empty attributes",
			args{},
			[]*saml.AttributeType{},
		},
		{
			"full attributes",
			args{
				email:            "email",
				fullName:         "fullname",
				givenName:        "givenname",
				surname:          "surname",
				userID:           "userid",
				username:         "username",
				customAttributes: nil,
			},
			[]*saml.AttributeType{
				{
					Name:           "Email",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"email"},
				},
				{
					Name:           "SurName",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"surname"},
				},
				{
					Name:           "FirstName",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"givenname"},
				},
				{
					Name:           "FullName",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"fullname"},
				},
				{
					Name:           "UserName",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"username"},
				},
				{
					Name:           "UserID",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"userid"},
				},
			},
		},
		{
			"full attributes with custom",
			args{
				email:     "email",
				fullName:  "fullname",
				givenName: "givenname",
				surname:   "surname",
				userID:    "userid",
				username:  "username",
				customAttributes: map[string]*CustomAttribute{
					"empty": {
						FriendlyName:   "fname",
						NameFormat:     "nameformat",
						AttributeValue: []string{""},
					},
					"key1": {
						FriendlyName:   "fname1",
						NameFormat:     "nameformat1",
						AttributeValue: []string{"first"},
					},
					"key2": {
						FriendlyName:   "fname2",
						NameFormat:     "nameformat2",
						AttributeValue: []string{"first", "second"},
					},
					"key3": {
						FriendlyName:   "fname3",
						NameFormat:     "nameformat3",
						AttributeValue: []string{"first", "second", "third"},
					},
				},
			},
			[]*saml.AttributeType{
				{
					Name:           "Email",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"email"},
				},
				{
					Name:           "SurName",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"surname"},
				},
				{
					Name:           "FirstName",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"givenname"},
				},
				{
					Name:           "FullName",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"fullname"},
				},
				{
					Name:           "UserName",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"username"},
				},
				{
					Name:           "UserID",
					NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
					AttributeValue: []string{"userid"},
				},
				{
					Name:           "empty",
					NameFormat:     "nameformat",
					FriendlyName:   "fname",
					AttributeValue: []string{""},
				},
				{
					Name:           "key1",
					NameFormat:     "nameformat1",
					FriendlyName:   "fname1",
					AttributeValue: []string{"first"},
				},
				{
					Name:           "key2",
					NameFormat:     "nameformat2",
					FriendlyName:   "fname2",
					AttributeValue: []string{"first", "second"},
				},
				{
					Name:           "key3",
					NameFormat:     "nameformat3",
					FriendlyName:   "fname3",
					AttributeValue: []string{"first", "second", "third"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &Attributes{
				email:            tt.args.email,
				fullName:         tt.args.fullName,
				givenName:        tt.args.givenName,
				surname:          tt.args.surname,
				userID:           tt.args.userID,
				username:         tt.args.username,
				customAttributes: tt.args.customAttributes,
			}
			assert.Equal(t, tt.res, attrs.GetSAML())
		})
	}
}
