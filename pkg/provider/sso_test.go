package provider

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/zitadel/saml/pkg/provider/mock"
	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml"
	"github.com/zitadel/saml/pkg/provider/xml/md"
	"github.com/zitadel/saml/pkg/provider/xml/xml_dsig"
)

func TestSSO_getAcsUrlAndBindingForResponse(t *testing.T) {
	type res struct {
		acs     string
		binding string
	}
	type args struct {
		sp             *serviceprovider.ServiceProvider
		requestBinding string
	}
	tests := []struct {
		name string
		args args
		res  res
	}{{
		"sp with post and redirect, default used",
		args{
			&serviceprovider.ServiceProvider{
				Metadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						AssertionConsumerService: []md.IndexedEndpointType{
							{Index: "1", IsDefault: "true", Binding: RedirectBinding, Location: "redirect"},
							{Index: "2", Binding: PostBinding, Location: "post"},
						},
					},
				},
			},
			RedirectBinding,
		},
		res{
			acs:     "redirect",
			binding: RedirectBinding,
		},
	},
		{
			"sp with post and redirect, first index used",
			args{
				&serviceprovider.ServiceProvider{
					Metadata: &md.EntityDescriptorType{
						SPSSODescriptor: &md.SPSSODescriptorType{
							AssertionConsumerService: []md.IndexedEndpointType{
								{Index: "1", Binding: RedirectBinding, Location: "redirect"},
								{Index: "2", Binding: PostBinding, Location: "post"},
							},
						},
					},
				},
				RedirectBinding,
			},
			res{
				acs:     "redirect",
				binding: RedirectBinding,
			},
		},
		{
			"sp with post and redirect, redirect used",
			args{
				&serviceprovider.ServiceProvider{
					Metadata: &md.EntityDescriptorType{
						SPSSODescriptor: &md.SPSSODescriptorType{
							AssertionConsumerService: []md.IndexedEndpointType{
								{Binding: RedirectBinding, Location: "redirect"},
								{Binding: PostBinding, Location: "post"},
							},
						},
					},
				},
				RedirectBinding,
			},
			res{
				acs:     "redirect",
				binding: RedirectBinding,
			},
		},
		{
			"sp with post and redirect, post used",
			args{
				&serviceprovider.ServiceProvider{
					Metadata: &md.EntityDescriptorType{
						SPSSODescriptor: &md.SPSSODescriptorType{
							AssertionConsumerService: []md.IndexedEndpointType{
								{Binding: RedirectBinding, Location: "redirect"},
								{Binding: PostBinding, Location: "post"},
							},
						},
					},
				},
				PostBinding,
			},
			res{
				acs:     "post",
				binding: PostBinding,
			},
		},
		{
			"sp with redirect, post used",
			args{
				&serviceprovider.ServiceProvider{
					Metadata: &md.EntityDescriptorType{
						SPSSODescriptor: &md.SPSSODescriptorType{
							AssertionConsumerService: []md.IndexedEndpointType{
								{Binding: RedirectBinding, Location: "redirect"},
							},
						},
					},
				},
				PostBinding,
			},
			res{
				acs:     "redirect",
				binding: RedirectBinding,
			},
		},
		{
			"sp with post, redirect used",
			args{
				&serviceprovider.ServiceProvider{
					Metadata: &md.EntityDescriptorType{
						SPSSODescriptor: &md.SPSSODescriptorType{
							AssertionConsumerService: []md.IndexedEndpointType{
								{Binding: PostBinding, Location: "post"},
							},
						},
					},
				},
				RedirectBinding,
			},
			res{
				acs:     "post",
				binding: PostBinding,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acs, binding := getAcsUrlAndBindingForResponse(tt.args.sp, tt.args.requestBinding)
			if acs != tt.res.acs && binding != tt.res.binding {
				t.Errorf("getAcsUrlAndBindingForResponse() got = %v/%v, want %v/%v", acs, binding, tt.res.acs, tt.res.binding)
				return
			}
		})
	}
}

func TestSSO_getAuthRequestFromRequest(t *testing.T) {
	type res struct {
		want *AuthRequestForm
		err  bool
	}
	tests := []struct {
		name string
		arg  *http.Request
		res  res
	}{
		{
			"parsing form error",
			&http.Request{URL: &url.URL{RawQuery: "invalid=%%param"}},
			res{
				nil,
				true,
			},
		},
		{
			"signed redirect binding",
			&http.Request{URL: &url.URL{RawQuery: "SAMLRequest=request&SAMLEncoding=encoding&RelayState=state&SigAlg=alg&Signature=sig"}},
			res{
				&AuthRequestForm{
					AuthRequest: "request",
					Encoding:    "encoding",
					RelayState:  "state",
					SigAlg:      "alg",
					Sig:         "sig",
					Binding:     RedirectBinding,
				},
				false,
			},
		},
		{
			"signed redirect binding without RelayState",
			&http.Request{URL: &url.URL{RawQuery: "SAMLRequest=request&SAMLEncoding=encoding&SigAlg=alg&Signature=sig"}},
			res{
				&AuthRequestForm{
					AuthRequest: "request",
					Encoding:    "encoding",
					RelayState:  "",
					SigAlg:      "alg",
					Sig:         "sig",
					Binding:     RedirectBinding,
				},
				false,
			},
		},
		{
			"unsigned redirect binding",
			&http.Request{URL: &url.URL{RawQuery: "SAMLRequest=request&SAMLEncoding=encoding&RelayState=state"}},
			res{
				&AuthRequestForm{
					AuthRequest: "request",
					Encoding:    "encoding",
					RelayState:  "state",
					SigAlg:      "",
					Sig:         "",
					Binding:     RedirectBinding,
				},
				false,
			},
		},
		{
			"post binding",
			&http.Request{
				Form: map[string][]string{
					"SAMLRequest": {"request"},
					"RelayState":  {"state"},
				},
				URL: &url.URL{RawQuery: ""}},
			res{
				&AuthRequestForm{
					AuthRequest: "request",
					Encoding:    "",
					RelayState:  "state",
					SigAlg:      "",
					Sig:         "",
					Binding:     PostBinding,
				},
				false,
			},
		},
		{
			"post binding without RelayState",
			&http.Request{
				Form: map[string][]string{
					"SAMLRequest": {"request"},
				},
				URL: &url.URL{RawQuery: ""}},
			res{
				&AuthRequestForm{
					AuthRequest: "request",
					Encoding:    "",
					RelayState:  "",
					SigAlg:      "",
					Sig:         "",
					Binding:     PostBinding,
				},
				false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getAuthRequestFromRequest(tt.arg)
			if (err != nil) != tt.res.err {
				t.Errorf("getAuthRequestFromRequest() error = %v, wantErr %v", err, tt.res.err)
			}
			if !reflect.DeepEqual(got, tt.res.want) {
				t.Errorf("getAuthRequestFromRequest() got = %v, want %v", got, tt.res.want)
			}
		})
	}
}

func TestSSO_certificateCheckNecessary(t *testing.T) {
	type args struct {
		sig      *xml_dsig.SignatureType
		metadata *md.EntityDescriptorType
	}
	tests := []struct {
		name string
		args args
		res  bool
	}{
		{
			"sig nil",
			args{
				sig:      nil,
				metadata: &md.EntityDescriptorType{},
			},
			false,
		},
		{
			"keyinfo nil",
			args{
				sig:      &xml_dsig.SignatureType{KeyInfo: nil},
				metadata: &md.EntityDescriptorType{},
			},
			false,
		},
		{
			"keydescriptor nil",
			args{
				sig: &xml_dsig.SignatureType{KeyInfo: &xml_dsig.KeyInfoType{}},
				metadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						KeyDescriptor: nil,
					},
				},
			},
			false,
		},
		{
			"keydescriptor length == 0",
			args{
				sig: &xml_dsig.SignatureType{KeyInfo: &xml_dsig.KeyInfoType{}},
				metadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						KeyDescriptor: []md.KeyDescriptorType{},
					},
				},
			},
			false,
		},
		{
			"check necessary",
			args{
				sig: &xml_dsig.SignatureType{KeyInfo: &xml_dsig.KeyInfoType{}},
				metadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						KeyDescriptor: []md.KeyDescriptorType{{Use: "test"}},
					},
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authRequestF := func() *xml_dsig.SignatureType {
				return tt.args.sig
			}
			metadataF := func() *md.EntityDescriptorType {
				return tt.args.metadata
			}

			gotF := certificateCheckNecessary(authRequestF, metadataF)
			got := gotF()
			if got != tt.res {
				t.Errorf("certificateCheckNecessary() got = %v, want %v", got, tt.res)
			}
		})
	}
}

func TestSSO_checkCertificate(t *testing.T) {
	type args struct {
		sig      *xml_dsig.SignatureType
		metadata *md.EntityDescriptorType
	}
	tests := []struct {
		name string
		args args
		err  bool
	}{
		{
			"keydescriptor length == 0",
			args{
				sig: &xml_dsig.SignatureType{KeyInfo: &xml_dsig.KeyInfoType{}},
				metadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						KeyDescriptor: []md.KeyDescriptorType{},
					},
				},
			},
			true,
		},
		{
			"x509data length == 0",
			args{
				sig: &xml_dsig.SignatureType{KeyInfo: &xml_dsig.KeyInfoType{X509Data: []xml_dsig.X509DataType{}}},
				metadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						KeyDescriptor: []md.KeyDescriptorType{{Use: "test"}},
					},
				},
			},
			true,
		},
		{
			"certificates equal",
			args{
				sig: &xml_dsig.SignatureType{KeyInfo: &xml_dsig.KeyInfoType{X509Data: []xml_dsig.X509DataType{{X509Certificate: "test"}}}},
				metadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						KeyDescriptor: []md.KeyDescriptorType{{Use: "test", KeyInfo: xml_dsig.KeyInfoType{X509Data: []xml_dsig.X509DataType{{X509Certificate: "test"}}}}},
					},
				},
			},
			false,
		},
		{
			"certificates not equal",
			args{
				sig: &xml_dsig.SignatureType{KeyInfo: &xml_dsig.KeyInfoType{X509Data: []xml_dsig.X509DataType{{X509Certificate: "test1"}}}},
				metadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						KeyDescriptor: []md.KeyDescriptorType{{Use: "test", KeyInfo: xml_dsig.KeyInfoType{X509Data: []xml_dsig.X509DataType{{X509Certificate: "test2"}}}}},
					},
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authRequestF := func() *xml_dsig.SignatureType {
				return tt.args.sig
			}
			metadataF := func() *md.EntityDescriptorType {
				return tt.args.metadata
			}

			gotF := checkCertificate(authRequestF, metadataF)
			got := gotF()
			if (got != nil) != tt.err {
				t.Errorf("checkCertificate() got = %v, want %v", got, tt.err)
			}
		})
	}
}

func TestSSO_ssoHandleFunc(t *testing.T) {
	type request struct {
		ID           string
		SAMLRequest  string
		Signature    string
		SigAlg       string
		SAMLEncoding string
		RelayState   string
		Binding      string
	}
	type res struct {
		code  int
		err   bool
		state string
	}
	type sp struct {
		entityID string
		metadata string
		err      error
	}
	type args struct {
		issuer           string
		metadataEndpoint string
		config           *IdentityProviderConfig
		certificate      string
		key              string
		request          request
		sp               sp
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"signed redirect request",
			args{
				issuer:           "http://localhost:50002",
				metadataEndpoint: "/saml/metadata",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints: &EndpointConfig{
						SingleSignOn: getEndpointPointer("/saml/SSO", "http://localhost:50002/saml/SSO"),
					},
				},
				certificate: "-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n",
				key:         "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq\nVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc\nWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2\ngIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a\nEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7\nLfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v\n4cxTNPn/AgMBAAECggEAF+rV9yH30Ysza8GwrXCR9qDN1Dp3QmmsavnXkonEvPoq\nEr2T3o0//6mBp6CLDboMQGQBjblJwl+3Y6PgZolvHAMOsMdHfYNPEo7FSzUBzEw+\nqRrs5HkMyvoPgfV6X8F97W3tiD4Q/AmHkMILl+MxbnfPXM54gWqPuwIqxY1uaCk5\nREwyb7WBon3rd58ceOI1SLRjod6SbqWBMMSN3cJ+5VEPObFjw/RlhNQ5rBI8G5Kt\nso2zBU5C4BB2CvqlWy98WDKJkTvWHbiTjZCy8BQ+gQ6UJM2vaNELFOVpuMGQnMIi\noWiX10Jg2e1gP9j3TdrohlGF8M3+TXjSFKNmeX0DUQKBgQDx7UazUWS5RtkgnjH9\nw2xH2xkstJVD7nAS8VTxNwcrgjVXPvTJha9El904obUjyRX7ppb02tuH5ML/bZh6\n9lL4bP5+SHcJ10e4q8CK/KAGHD6BYAbaGXRq0CoSk5a3vv5XPdob4T5qKCIHFpnu\nMfbvdbEoameLOyRYOGu/yVZIiwKBgQDGQs7FRTisHV0xooiRmlvYF0dcd19qpLed\nqhgJNqBPOTEvvGvJNRoi39haEY3cuTqsxZ5FAlFlVFMUUozz+d0xBLLInoVY/Y4h\nhSdGmdw/A6oHodLqyEp3N5RZNdLlh8/nDS3xXzMotAl75bW5kc2ttcRhRdtyNJ9Z\nup0PgppO3QKBgEC45upAQz8iCiKkz+EA8C4FGqYQJcLHvmoC8GOcAioMqrKNoDVt\ns2cZbdChynEpcd0iQ058YrDnbZeiPWHgFnBp0Gf+gQI7+u8X2+oTDci0s7Au/YZJ\nuxB8YlUX8QF1clvqqzg8OVNzKy9UR5gm+9YyWVPjq5HfH6kOZx0nAxNjAoGAERt8\nqgsCC9/wxbKnpCC0oh3IG5N1WUdjTKh7sHfVN2DQ/LR+fHsniTDVg1gWbKBTDsty\nj7PWgC7ZiFxjKz45NtyX7LW4/efLFttdezsVhR500nnFMFseCdFy7Iu3afThHKfH\nehdj27RFSTqWBrAtFjsj+dzERcOCqIRwvwDe/cUCgYEA5+1mzVXDVjKsWylKJPk+\nZZA4LUfvmTj3VLNDZrlSAI/xEikCFio0QWEA2TQYTAwbXTrKwQSeHQRhv7OTc1h+\nMhpAgvs189ze5J4jiNmULEkkrO+Cxxnw8tyV+UFRZtzW9gUoVBwXiZ/Wbl9sfnlO\nwLJHc0j6OltPcPJmxHP8gQI=\n-----END PRIVATE KEY-----\n",
				request: request{
					ID:          "test",
					Binding:     RedirectBinding,
					SAMLRequest: url.QueryEscape("nJJBj9MwEIX/ijX3NG6a7DbWJlLZClFpYatN4cBt6k6oJccungmw/x61XaQioRy42vP5ved5D4yDP5nVKMfwQt9HYlG/Bh/YnC8aGFMwEdmxCTgQG7GmW318MsVMG2SmJC4GuEFO08wpRYk2elCbdQPukFlNd/c9LQpczPve6r3taVHWdbWoal3bfr7c03JJc1BfKLGLoYFipkFtmEfaBBYM0kChiyLTZVbc7XRtyntTVrOyrr6CWhOLCygX8ihyMnnuo0V/jCym0loX+dl33nXPoFZ/Ij3GwONAqaP0w1n6/PL0D3qptb7CaBnU9i3bOxcOLnyb/oj9dYjNh91um22fux20l2WYS7Kk3sc0oEw/cj5xh6y/jBoK4uQV2gmfAwkeUPAhv5Fq30rwCQfarLfRO/v6H/KSMLCjIKBW3sefj4lQqAFJI0HeXiX/rlr7OwAA//8="),
					RelayState:  url.QueryEscape("K6LS7mdqUO4SGedbfa8nBIyX-7K8gGbrHMqIMwVn6zCKLLoADHjEHUAm"),
					Signature:   url.QueryEscape("PWZ6JPNpAGE7mYLKD3dCUG9AZcThrMRQGtvdv31ewx3hms5Oglc677iAUEcbIBrvKtMrCPVwXPNxT6wQ0rg4qIgyKgoyS53ZTaxaFHPrB7wkkzqtK7GvWgdEqceT8iooK5SCLHFMJ3m30LqEbX7zFw62yE34+e7ypfZSM5Lrf0QFwPzX+LNCuYA+Ob9D5SKc132tn21J2vBRmNJ1zCY0ksRzQfyfErjAzcGVx8qK9jpaeyvsVBZSkH/I6+1hb8lQWE48xala9NbqfbMATGBCQj1UvpVMMfp6PE7KPk5Y1YDeSqPeRIEKH+Gnip6Hve5Ji1aiRp5bytVf1VHwTHSq8w=="),
					SigAlg:      url.QueryEscape("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
				},
				sp: sp{
					entityID: "http://localhost:8000/saml/metadata",
					metadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.797Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.796923Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
				},
			},
			res{
				code:  303,
				state: "",
				err:   false,
			}},
		{
			"redirect request without RelayState",
			args{
				issuer:           "http://localhost:50002",
				metadataEndpoint: "/saml/metadata",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints: &EndpointConfig{
						SingleSignOn: getEndpointPointer("/saml/SSO", "http://localhost:50002/saml/SSO"),
					},
				},
				certificate: "-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n",
				key:         "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq\nVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc\nWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2\ngIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a\nEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7\nLfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v\n4cxTNPn/AgMBAAECggEAF+rV9yH30Ysza8GwrXCR9qDN1Dp3QmmsavnXkonEvPoq\nEr2T3o0//6mBp6CLDboMQGQBjblJwl+3Y6PgZolvHAMOsMdHfYNPEo7FSzUBzEw+\nqRrs5HkMyvoPgfV6X8F97W3tiD4Q/AmHkMILl+MxbnfPXM54gWqPuwIqxY1uaCk5\nREwyb7WBon3rd58ceOI1SLRjod6SbqWBMMSN3cJ+5VEPObFjw/RlhNQ5rBI8G5Kt\nso2zBU5C4BB2CvqlWy98WDKJkTvWHbiTjZCy8BQ+gQ6UJM2vaNELFOVpuMGQnMIi\noWiX10Jg2e1gP9j3TdrohlGF8M3+TXjSFKNmeX0DUQKBgQDx7UazUWS5RtkgnjH9\nw2xH2xkstJVD7nAS8VTxNwcrgjVXPvTJha9El904obUjyRX7ppb02tuH5ML/bZh6\n9lL4bP5+SHcJ10e4q8CK/KAGHD6BYAbaGXRq0CoSk5a3vv5XPdob4T5qKCIHFpnu\nMfbvdbEoameLOyRYOGu/yVZIiwKBgQDGQs7FRTisHV0xooiRmlvYF0dcd19qpLed\nqhgJNqBPOTEvvGvJNRoi39haEY3cuTqsxZ5FAlFlVFMUUozz+d0xBLLInoVY/Y4h\nhSdGmdw/A6oHodLqyEp3N5RZNdLlh8/nDS3xXzMotAl75bW5kc2ttcRhRdtyNJ9Z\nup0PgppO3QKBgEC45upAQz8iCiKkz+EA8C4FGqYQJcLHvmoC8GOcAioMqrKNoDVt\ns2cZbdChynEpcd0iQ058YrDnbZeiPWHgFnBp0Gf+gQI7+u8X2+oTDci0s7Au/YZJ\nuxB8YlUX8QF1clvqqzg8OVNzKy9UR5gm+9YyWVPjq5HfH6kOZx0nAxNjAoGAERt8\nqgsCC9/wxbKnpCC0oh3IG5N1WUdjTKh7sHfVN2DQ/LR+fHsniTDVg1gWbKBTDsty\nj7PWgC7ZiFxjKz45NtyX7LW4/efLFttdezsVhR500nnFMFseCdFy7Iu3afThHKfH\nehdj27RFSTqWBrAtFjsj+dzERcOCqIRwvwDe/cUCgYEA5+1mzVXDVjKsWylKJPk+\nZZA4LUfvmTj3VLNDZrlSAI/xEikCFio0QWEA2TQYTAwbXTrKwQSeHQRhv7OTc1h+\nMhpAgvs189ze5J4jiNmULEkkrO+Cxxnw8tyV+UFRZtzW9gUoVBwXiZ/Wbl9sfnlO\nwLJHc0j6OltPcPJmxHP8gQI=\n-----END PRIVATE KEY-----\n",
				request: request{
					ID:          "test",
					Binding:     RedirectBinding,
					SAMLRequest: url.QueryEscape("nJJBj9MwEIX/ijX3NG6a7DbWJlLZClFpYatN4cBt6k6oJccungmw/x61XaQioRy42vP5ved5D4yDP5nVKMfwQt9HYlG/Bh/YnC8aGFMwEdmxCTgQG7GmW318MsVMG2SmJC4GuEFO08wpRYk2elCbdQPukFlNd/c9LQpczPve6r3taVHWdbWoal3bfr7c03JJc1BfKLGLoYFipkFtmEfaBBYM0kChiyLTZVbc7XRtyntTVrOyrr6CWhOLCygX8ihyMnnuo0V/jCym0loX+dl33nXPoFZ/Ij3GwONAqaP0w1n6/PL0D3qptb7CaBnU9i3bOxcOLnyb/oj9dYjNh91um22fux20l2WYS7Kk3sc0oEw/cj5xh6y/jBoK4uQV2gmfAwkeUPAhv5Fq30rwCQfarLfRO/v6H/KSMLCjIKBW3sefj4lQqAFJI0HeXiX/rlr7OwAA//8="),
				},
				sp: sp{
					entityID: "http://localhost:8000/saml/metadata",
					metadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.797Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.796923Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
				},
			},
			res{
				code:  303,
				state: "",
				err:   false,
			}},
		{
			"redirect request form parse error",
			args{
				issuer:           "http://localhost:50002",
				metadataEndpoint: "/saml/metadata",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints: &EndpointConfig{
						SingleSignOn: getEndpointPointer("/saml/SSO", "http://localhost:50002/saml/SSO"),
					},
				},
				certificate: "-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n",
				key:         "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq\nVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc\nWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2\ngIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a\nEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7\nLfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v\n4cxTNPn/AgMBAAECggEAF+rV9yH30Ysza8GwrXCR9qDN1Dp3QmmsavnXkonEvPoq\nEr2T3o0//6mBp6CLDboMQGQBjblJwl+3Y6PgZolvHAMOsMdHfYNPEo7FSzUBzEw+\nqRrs5HkMyvoPgfV6X8F97W3tiD4Q/AmHkMILl+MxbnfPXM54gWqPuwIqxY1uaCk5\nREwyb7WBon3rd58ceOI1SLRjod6SbqWBMMSN3cJ+5VEPObFjw/RlhNQ5rBI8G5Kt\nso2zBU5C4BB2CvqlWy98WDKJkTvWHbiTjZCy8BQ+gQ6UJM2vaNELFOVpuMGQnMIi\noWiX10Jg2e1gP9j3TdrohlGF8M3+TXjSFKNmeX0DUQKBgQDx7UazUWS5RtkgnjH9\nw2xH2xkstJVD7nAS8VTxNwcrgjVXPvTJha9El904obUjyRX7ppb02tuH5ML/bZh6\n9lL4bP5+SHcJ10e4q8CK/KAGHD6BYAbaGXRq0CoSk5a3vv5XPdob4T5qKCIHFpnu\nMfbvdbEoameLOyRYOGu/yVZIiwKBgQDGQs7FRTisHV0xooiRmlvYF0dcd19qpLed\nqhgJNqBPOTEvvGvJNRoi39haEY3cuTqsxZ5FAlFlVFMUUozz+d0xBLLInoVY/Y4h\nhSdGmdw/A6oHodLqyEp3N5RZNdLlh8/nDS3xXzMotAl75bW5kc2ttcRhRdtyNJ9Z\nup0PgppO3QKBgEC45upAQz8iCiKkz+EA8C4FGqYQJcLHvmoC8GOcAioMqrKNoDVt\ns2cZbdChynEpcd0iQ058YrDnbZeiPWHgFnBp0Gf+gQI7+u8X2+oTDci0s7Au/YZJ\nuxB8YlUX8QF1clvqqzg8OVNzKy9UR5gm+9YyWVPjq5HfH6kOZx0nAxNjAoGAERt8\nqgsCC9/wxbKnpCC0oh3IG5N1WUdjTKh7sHfVN2DQ/LR+fHsniTDVg1gWbKBTDsty\nj7PWgC7ZiFxjKz45NtyX7LW4/efLFttdezsVhR500nnFMFseCdFy7Iu3afThHKfH\nehdj27RFSTqWBrAtFjsj+dzERcOCqIRwvwDe/cUCgYEA5+1mzVXDVjKsWylKJPk+\nZZA4LUfvmTj3VLNDZrlSAI/xEikCFio0QWEA2TQYTAwbXTrKwQSeHQRhv7OTc1h+\nMhpAgvs189ze5J4jiNmULEkkrO+Cxxnw8tyV+UFRZtzW9gUoVBwXiZ/Wbl9sfnlO\nwLJHc0j6OltPcPJmxHP8gQI=\n-----END PRIVATE KEY-----\n",
				request: request{
					ID:          "test",
					Binding:     RedirectBinding,
					SAMLRequest: "%%param",
					RelayState:  "K6LS7mdqUO4SGedbfa8nBIyX-7K8gGbrHMqIMwVn6zCKLLoADHjEHUAm",
					Signature:   "",
					SigAlg:      "",
				},
				sp: sp{
					entityID: "http://localhost:8000/saml/metadata",
					metadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.797Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.796923Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
				},
			},
			res{
				code:  500,
				state: "",
				err:   false,
			}},
		{
			"redirect request decode error",
			args{
				issuer:           "http://localhost:50002",
				metadataEndpoint: "/saml/metadata",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints: &EndpointConfig{
						SingleSignOn: getEndpointPointer("/saml/SSO", "http://localhost:50002/saml/SSO"),
					},
				},
				certificate: "-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n",
				key:         "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq\nVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc\nWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2\ngIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a\nEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7\nLfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v\n4cxTNPn/AgMBAAECggEAF+rV9yH30Ysza8GwrXCR9qDN1Dp3QmmsavnXkonEvPoq\nEr2T3o0//6mBp6CLDboMQGQBjblJwl+3Y6PgZolvHAMOsMdHfYNPEo7FSzUBzEw+\nqRrs5HkMyvoPgfV6X8F97W3tiD4Q/AmHkMILl+MxbnfPXM54gWqPuwIqxY1uaCk5\nREwyb7WBon3rd58ceOI1SLRjod6SbqWBMMSN3cJ+5VEPObFjw/RlhNQ5rBI8G5Kt\nso2zBU5C4BB2CvqlWy98WDKJkTvWHbiTjZCy8BQ+gQ6UJM2vaNELFOVpuMGQnMIi\noWiX10Jg2e1gP9j3TdrohlGF8M3+TXjSFKNmeX0DUQKBgQDx7UazUWS5RtkgnjH9\nw2xH2xkstJVD7nAS8VTxNwcrgjVXPvTJha9El904obUjyRX7ppb02tuH5ML/bZh6\n9lL4bP5+SHcJ10e4q8CK/KAGHD6BYAbaGXRq0CoSk5a3vv5XPdob4T5qKCIHFpnu\nMfbvdbEoameLOyRYOGu/yVZIiwKBgQDGQs7FRTisHV0xooiRmlvYF0dcd19qpLed\nqhgJNqBPOTEvvGvJNRoi39haEY3cuTqsxZ5FAlFlVFMUUozz+d0xBLLInoVY/Y4h\nhSdGmdw/A6oHodLqyEp3N5RZNdLlh8/nDS3xXzMotAl75bW5kc2ttcRhRdtyNJ9Z\nup0PgppO3QKBgEC45upAQz8iCiKkz+EA8C4FGqYQJcLHvmoC8GOcAioMqrKNoDVt\ns2cZbdChynEpcd0iQ058YrDnbZeiPWHgFnBp0Gf+gQI7+u8X2+oTDci0s7Au/YZJ\nuxB8YlUX8QF1clvqqzg8OVNzKy9UR5gm+9YyWVPjq5HfH6kOZx0nAxNjAoGAERt8\nqgsCC9/wxbKnpCC0oh3IG5N1WUdjTKh7sHfVN2DQ/LR+fHsniTDVg1gWbKBTDsty\nj7PWgC7ZiFxjKz45NtyX7LW4/efLFttdezsVhR500nnFMFseCdFy7Iu3afThHKfH\nehdj27RFSTqWBrAtFjsj+dzERcOCqIRwvwDe/cUCgYEA5+1mzVXDVjKsWylKJPk+\nZZA4LUfvmTj3VLNDZrlSAI/xEikCFio0QWEA2TQYTAwbXTrKwQSeHQRhv7OTc1h+\nMhpAgvs189ze5J4jiNmULEkkrO+Cxxnw8tyV+UFRZtzW9gUoVBwXiZ/Wbl9sfnlO\nwLJHc0j6OltPcPJmxHP8gQI=\n-----END PRIVATE KEY-----\n",
				request: request{
					ID:          "test",
					Binding:     RedirectBinding,
					SAMLRequest: "test",
					RelayState:  "K6LS7mdqUO4SGedbfa8nBIyX-7K8gGbrHMqIMwVn6zCKLLoADHjEHUAm",
					Signature:   "",
					SigAlg:      "",
				},
				sp: sp{
					entityID: "http://localhost:8000/saml/metadata",
					metadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.797Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.796923Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
				},
			},
			res{
				code:  200,
				state: StatusCodeRequestDenied,
				err:   false,
			}},
		{
			"redirect request unknown service provider",
			args{
				issuer:           "http://localhost:50002",
				metadataEndpoint: "/saml/metadata",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints: &EndpointConfig{
						SingleSignOn: getEndpointPointer("/saml/SSO", "http://localhost:50002/saml/SSO"),
					},
				},
				certificate: "-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n",
				key:         "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq\nVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc\nWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2\ngIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a\nEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7\nLfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v\n4cxTNPn/AgMBAAECggEAF+rV9yH30Ysza8GwrXCR9qDN1Dp3QmmsavnXkonEvPoq\nEr2T3o0//6mBp6CLDboMQGQBjblJwl+3Y6PgZolvHAMOsMdHfYNPEo7FSzUBzEw+\nqRrs5HkMyvoPgfV6X8F97W3tiD4Q/AmHkMILl+MxbnfPXM54gWqPuwIqxY1uaCk5\nREwyb7WBon3rd58ceOI1SLRjod6SbqWBMMSN3cJ+5VEPObFjw/RlhNQ5rBI8G5Kt\nso2zBU5C4BB2CvqlWy98WDKJkTvWHbiTjZCy8BQ+gQ6UJM2vaNELFOVpuMGQnMIi\noWiX10Jg2e1gP9j3TdrohlGF8M3+TXjSFKNmeX0DUQKBgQDx7UazUWS5RtkgnjH9\nw2xH2xkstJVD7nAS8VTxNwcrgjVXPvTJha9El904obUjyRX7ppb02tuH5ML/bZh6\n9lL4bP5+SHcJ10e4q8CK/KAGHD6BYAbaGXRq0CoSk5a3vv5XPdob4T5qKCIHFpnu\nMfbvdbEoameLOyRYOGu/yVZIiwKBgQDGQs7FRTisHV0xooiRmlvYF0dcd19qpLed\nqhgJNqBPOTEvvGvJNRoi39haEY3cuTqsxZ5FAlFlVFMUUozz+d0xBLLInoVY/Y4h\nhSdGmdw/A6oHodLqyEp3N5RZNdLlh8/nDS3xXzMotAl75bW5kc2ttcRhRdtyNJ9Z\nup0PgppO3QKBgEC45upAQz8iCiKkz+EA8C4FGqYQJcLHvmoC8GOcAioMqrKNoDVt\ns2cZbdChynEpcd0iQ058YrDnbZeiPWHgFnBp0Gf+gQI7+u8X2+oTDci0s7Au/YZJ\nuxB8YlUX8QF1clvqqzg8OVNzKy9UR5gm+9YyWVPjq5HfH6kOZx0nAxNjAoGAERt8\nqgsCC9/wxbKnpCC0oh3IG5N1WUdjTKh7sHfVN2DQ/LR+fHsniTDVg1gWbKBTDsty\nj7PWgC7ZiFxjKz45NtyX7LW4/efLFttdezsVhR500nnFMFseCdFy7Iu3afThHKfH\nehdj27RFSTqWBrAtFjsj+dzERcOCqIRwvwDe/cUCgYEA5+1mzVXDVjKsWylKJPk+\nZZA4LUfvmTj3VLNDZrlSAI/xEikCFio0QWEA2TQYTAwbXTrKwQSeHQRhv7OTc1h+\nMhpAgvs189ze5J4jiNmULEkkrO+Cxxnw8tyV+UFRZtzW9gUoVBwXiZ/Wbl9sfnlO\nwLJHc0j6OltPcPJmxHP8gQI=\n-----END PRIVATE KEY-----\n",
				request: request{
					ID:          "test",
					Binding:     RedirectBinding,
					SAMLRequest: url.QueryEscape("nJJBj9MwEIX/ijX3NG6a7DbWJlLZClFpYatN4cBt6k6oJccungmw/x61XaQioRy42vP5ved5D4yDP5nVKMfwQt9HYlG/Bh/YnC8aGFMwEdmxCTgQG7GmW318MsVMG2SmJC4GuEFO08wpRYk2elCbdQPukFlNd/c9LQpczPve6r3taVHWdbWoal3bfr7c03JJc1BfKLGLoYFipkFtmEfaBBYM0kChiyLTZVbc7XRtyntTVrOyrr6CWhOLCygX8ihyMnnuo0V/jCym0loX+dl33nXPoFZ/Ij3GwONAqaP0w1n6/PL0D3qptb7CaBnU9i3bOxcOLnyb/oj9dYjNh91um22fux20l2WYS7Kk3sc0oEw/cj5xh6y/jBoK4uQV2gmfAwkeUPAhv5Fq30rwCQfarLfRO/v6H/KSMLCjIKBW3sefj4lQqAFJI0HeXiX/rlr7OwAA//8="),
					RelayState:  url.QueryEscape("K6LS7mdqUO4SGedbfa8nBIyX-7K8gGbrHMqIMwVn6zCKLLoADHjEHUAm"),
					Signature:   url.QueryEscape("PWZ6JPNpAGE7mYLKD3dCUG9AZcThrMRQGtvdv31ewx3hms5Oglc677iAUEcbIBrvKtMrCPVwXPNxT6wQ0rg4qIgyKgoyS53ZTaxaFHPrB7wkkzqtK7GvWgdEqceT8iooK5SCLHFMJ3m30LqEbX7zFw62yE34+e7ypfZSM5Lrf0QFwPzX+LNCuYA+Ob9D5SKc132tn21J2vBRmNJ1zCY0ksRzQfyfErjAzcGVx8qK9jpaeyvsVBZSkH/I6+1hb8lQWE48xala9NbqfbMATGBCQj1UvpVMMfp6PE7KPk5Y1YDeSqPeRIEKH+Gnip6Hve5Ji1aiRp5bytVf1VHwTHSq8w=="),
					SigAlg:      url.QueryEscape("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
				},
				sp: sp{
					entityID: "http://localhost:8000/saml/metadata",
					metadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.797Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.796923Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
					err:      fmt.Errorf("unknown"),
				},
			},
			res{
				code:  200,
				state: StatusCodeRequestDenied,
				err:   false,
			}},
		{
			"redirect request unknown service provider",
			args{
				issuer:           "http://localhost:50002",
				metadataEndpoint: "/saml/metadata",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints: &EndpointConfig{
						SingleSignOn: getEndpointPointer("/saml/SSO", "http://localhost:50002/saml/SSO"),
					},
				},
				certificate: "-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n",
				key:         "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq\nVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc\nWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2\ngIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a\nEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7\nLfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v\n4cxTNPn/AgMBAAECggEAF+rV9yH30Ysza8GwrXCR9qDN1Dp3QmmsavnXkonEvPoq\nEr2T3o0//6mBp6CLDboMQGQBjblJwl+3Y6PgZolvHAMOsMdHfYNPEo7FSzUBzEw+\nqRrs5HkMyvoPgfV6X8F97W3tiD4Q/AmHkMILl+MxbnfPXM54gWqPuwIqxY1uaCk5\nREwyb7WBon3rd58ceOI1SLRjod6SbqWBMMSN3cJ+5VEPObFjw/RlhNQ5rBI8G5Kt\nso2zBU5C4BB2CvqlWy98WDKJkTvWHbiTjZCy8BQ+gQ6UJM2vaNELFOVpuMGQnMIi\noWiX10Jg2e1gP9j3TdrohlGF8M3+TXjSFKNmeX0DUQKBgQDx7UazUWS5RtkgnjH9\nw2xH2xkstJVD7nAS8VTxNwcrgjVXPvTJha9El904obUjyRX7ppb02tuH5ML/bZh6\n9lL4bP5+SHcJ10e4q8CK/KAGHD6BYAbaGXRq0CoSk5a3vv5XPdob4T5qKCIHFpnu\nMfbvdbEoameLOyRYOGu/yVZIiwKBgQDGQs7FRTisHV0xooiRmlvYF0dcd19qpLed\nqhgJNqBPOTEvvGvJNRoi39haEY3cuTqsxZ5FAlFlVFMUUozz+d0xBLLInoVY/Y4h\nhSdGmdw/A6oHodLqyEp3N5RZNdLlh8/nDS3xXzMotAl75bW5kc2ttcRhRdtyNJ9Z\nup0PgppO3QKBgEC45upAQz8iCiKkz+EA8C4FGqYQJcLHvmoC8GOcAioMqrKNoDVt\ns2cZbdChynEpcd0iQ058YrDnbZeiPWHgFnBp0Gf+gQI7+u8X2+oTDci0s7Au/YZJ\nuxB8YlUX8QF1clvqqzg8OVNzKy9UR5gm+9YyWVPjq5HfH6kOZx0nAxNjAoGAERt8\nqgsCC9/wxbKnpCC0oh3IG5N1WUdjTKh7sHfVN2DQ/LR+fHsniTDVg1gWbKBTDsty\nj7PWgC7ZiFxjKz45NtyX7LW4/efLFttdezsVhR500nnFMFseCdFy7Iu3afThHKfH\nehdj27RFSTqWBrAtFjsj+dzERcOCqIRwvwDe/cUCgYEA5+1mzVXDVjKsWylKJPk+\nZZA4LUfvmTj3VLNDZrlSAI/xEikCFio0QWEA2TQYTAwbXTrKwQSeHQRhv7OTc1h+\nMhpAgvs189ze5J4jiNmULEkkrO+Cxxnw8tyV+UFRZtzW9gUoVBwXiZ/Wbl9sfnlO\nwLJHc0j6OltPcPJmxHP8gQI=\n-----END PRIVATE KEY-----\n",
				request: request{
					ID:          "test",
					Binding:     RedirectBinding,
					SAMLRequest: url.QueryEscape("nJJBj9MwEIX/ijX3NG6a7DbWJlLZClFpYatN4cBt6k6oJccungmw/x61XaQioRy42vP5ved5D4yDP5nVKMfwQt9HYlG/Bh/YnC8aGFMwEdmxCTgQG7GmW318MsVMG2SmJC4GuEFO08wpRYk2elCbdQPukFlNd/c9LQpczPve6r3taVHWdbWoal3bfr7c03JJc1BfKLGLoYFipkFtmEfaBBYM0kChiyLTZVbc7XRtyntTVrOyrr6CWhOLCygX8ihyMnnuo0V/jCym0loX+dl33nXPoFZ/Ij3GwONAqaP0w1n6/PL0D3qptb7CaBnU9i3bOxcOLnyb/oj9dYjNh91um22fux20l2WYS7Kk3sc0oEw/cj5xh6y/jBoK4uQV2gmfAwkeUPAhv5Fq30rwCQfarLfRO/v6H/KSMLCjIKBW3sefj4lQqAFJI0HeXiX/rlr7OwAA//8="),
					RelayState:  url.QueryEscape("K6LS7mdqUO4SGedbfa8nBIyX-7K8gGbrHMqIMwVn6zCKLLoADHjEHUAm"),
					Signature:   url.QueryEscape("PWZ6JPNpAGE7mYLKD3dCUG9AZcThrMRQGtvdv31ewx3hms5Oglc677iAUEcbIBrvKtMrCPVwXPNxT6wQ0rg4qIgyKgoyS53ZTaxaFHPrB7wkkzqtK7GvWgdEqceT8iooK5SCLHFMJ3m30LqEbX7zFw62yE34+e7ypfZSM5Lrf0QFwPzX+LNCuYA+Ob9D5SKc132tn21J2vBRmNJ1zCY0ksRzQfyfErjAzcGVx8qK9jpaeyvsVBZSkH/I6+1hb8lQWE48xala9NbqfbMATGBCQj1UvpVMMfp6PE7KPk5Y1YDeSqPeRIEKH+Gnip6Hve5Ji1aiRp5bytVf1VHwTHSq8w=="),
					SigAlg:      url.QueryEscape("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
				},
				sp: sp{
					entityID: "http://localhost:8000/saml/metadata",
					metadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.797Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-28T11:32:04.796923Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
					err:      fmt.Errorf("unknown"),
				},
			},
			res{
				code:  200,
				state: StatusCodeRequestDenied,
				err:   false,
			}},
		{
			"signed post request",
			args{
				issuer:           "http://localhost:8080",
				metadataEndpoint: "/saml/metadata",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints: &EndpointConfig{
						SingleSignOn: getEndpointPointer("/saml/SSO", "http://localhost:8080/saml/v2/SSO"),
					},
				},
				certificate: "-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n",
				key:         "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq\nVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc\nWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2\ngIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a\nEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7\nLfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v\n4cxTNPn/AgMBAAECggEAF+rV9yH30Ysza8GwrXCR9qDN1Dp3QmmsavnXkonEvPoq\nEr2T3o0//6mBp6CLDboMQGQBjblJwl+3Y6PgZolvHAMOsMdHfYNPEo7FSzUBzEw+\nqRrs5HkMyvoPgfV6X8F97W3tiD4Q/AmHkMILl+MxbnfPXM54gWqPuwIqxY1uaCk5\nREwyb7WBon3rd58ceOI1SLRjod6SbqWBMMSN3cJ+5VEPObFjw/RlhNQ5rBI8G5Kt\nso2zBU5C4BB2CvqlWy98WDKJkTvWHbiTjZCy8BQ+gQ6UJM2vaNELFOVpuMGQnMIi\noWiX10Jg2e1gP9j3TdrohlGF8M3+TXjSFKNmeX0DUQKBgQDx7UazUWS5RtkgnjH9\nw2xH2xkstJVD7nAS8VTxNwcrgjVXPvTJha9El904obUjyRX7ppb02tuH5ML/bZh6\n9lL4bP5+SHcJ10e4q8CK/KAGHD6BYAbaGXRq0CoSk5a3vv5XPdob4T5qKCIHFpnu\nMfbvdbEoameLOyRYOGu/yVZIiwKBgQDGQs7FRTisHV0xooiRmlvYF0dcd19qpLed\nqhgJNqBPOTEvvGvJNRoi39haEY3cuTqsxZ5FAlFlVFMUUozz+d0xBLLInoVY/Y4h\nhSdGmdw/A6oHodLqyEp3N5RZNdLlh8/nDS3xXzMotAl75bW5kc2ttcRhRdtyNJ9Z\nup0PgppO3QKBgEC45upAQz8iCiKkz+EA8C4FGqYQJcLHvmoC8GOcAioMqrKNoDVt\ns2cZbdChynEpcd0iQ058YrDnbZeiPWHgFnBp0Gf+gQI7+u8X2+oTDci0s7Au/YZJ\nuxB8YlUX8QF1clvqqzg8OVNzKy9UR5gm+9YyWVPjq5HfH6kOZx0nAxNjAoGAERt8\nqgsCC9/wxbKnpCC0oh3IG5N1WUdjTKh7sHfVN2DQ/LR+fHsniTDVg1gWbKBTDsty\nj7PWgC7ZiFxjKz45NtyX7LW4/efLFttdezsVhR500nnFMFseCdFy7Iu3afThHKfH\nehdj27RFSTqWBrAtFjsj+dzERcOCqIRwvwDe/cUCgYEA5+1mzVXDVjKsWylKJPk+\nZZA4LUfvmTj3VLNDZrlSAI/xEikCFio0QWEA2TQYTAwbXTrKwQSeHQRhv7OTc1h+\nMhpAgvs189ze5J4jiNmULEkkrO+Cxxnw8tyV+UFRZtzW9gUoVBwXiZ/Wbl9sfnlO\nwLJHc0j6OltPcPJmxHP8gQI=\n-----END PRIVATE KEY-----\n",
				request: request{
					ID:          "test",
					Binding:     PostBinding,
					SAMLRequest: "PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBJRD0iaWQtMjA4ZmZjZDllODFiNDU4Y2RlY2RiMTNlNWVkNDdhZTg3ODRmNzU2MiIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMjMtMDQtMDZUMDg6MTI6NTkuODEyWiIgRGVzdGluYXRpb249Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9zYW1sL3YyL1NTTyIgQXNzZXJ0aW9uQ29uc3VtZXJTZXJ2aWNlVVJMPSJodHRwOi8vbG9jYWxob3N0OjgwMDAvc2FtbC9hY3MiIFByb3RvY29sQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUE9TVCI+PHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwOi8vbG9jYWxob3N0OjgwMDAvc2FtbC9tZXRhZGF0YTwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+PGRzOlJlZmVyZW5jZSBVUkk9IiNpZC0yMDhmZmNkOWU4MWI0NThjZGVjZGIxM2U1ZWQ0N2FlODc4NGY3NTYyIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT5TY2NEc0pIaFIvTHRGM25sRmI0SnFUdHRaWHM9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPmZvemhzL1dSUEJyeUtCR21wdE5vNWc0ZVJMdUYwaXNVazUwaCtpM0hpVlRGMCtCZ0NiQUNhZWNTSnhxK2xzS2VtSUoxdWdGK0NDekE4KzZyVmdOWE5kbklIRUJleXdRb1Nhc3dJOHFURm5BcTdSMjlVMmdIcDhoQmNTNk5BVHJxNldsWnBERllwWmZrUEtpbTBEdEJaK1dHM3lNQW9pNmlJZ1dvOVRLNVp5dWl6VzFMNGtTN1BiK1F4ZktEMVFaNU1ieVZGUVE5TWRHQ2lJcGtJOXRFOVpxcU5iS25XdnBsZk9RUi9mSTRQYU5MSllaSHpnbW9kWERobGVqa1RtVGFoYXhEYVB4dHljblZxaWkvMldwVk1aaVZDUTFsWEgxc2VNS24xK0ZtNkdCUW52VDdvS01vMzZaVkF4Qk5TVFIwTmNaTVQzM1FRWXNOVTJQNjZ5akJjdz09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlDdkRDQ0FhUUNDUUNIZUV0ZHJVSWc5REFOQmdrcWhraUc5dzBCQVFzRkFEQWdNUjR3SEFZRFZRUUREQlZ0ZVhObGNuWnBZMlV1WlhoaGJYQnNaUzVqYjIwd0hoY05Nak13TkRBMU1UVXdPVEEzV2hjTk16TXdOREF5TVRVd09UQTNXakFnTVI0d0hBWURWUVFEREJWdGVYTmxjblpwWTJVdVpYaGhiWEJzWlM1amIyMHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDN2QxcDArV3dvUHRFb2ZnK1pXTzNtNjdyYTZEUXJBbDlJbUx2djh3WXkyQUFsc1hsdzBWaEVDV1ZvRVhmZVdCaWV1aW8wMHF0MGdDQnBiZytMMC9HazBRbFRWcWh3cGhVZDJ0OTRhcERiODZtWEVBQzE2VGlEcjFFZGZXMjZOVVd0cFFVSzdWUXU1MUVqYThMalo4ZjJqeUhPWTFBUXdxbktXc0wxQkV3YU5mTUs4TWRpeXJ0c2xOZmpLemk1eGJ2QytOQTFMNndES3pIait2Mm1HYy9wNEhLRmpoczlrZTRXdFZWajZRak1aRlNack5VcGRJWlFoNytoUG9tWlVwNS9kR2NZbHFxY2V6d0RYdWkxa0hpT1U3emJncERuZ1ZkYWFkYU5sVFNrYlRUTHA2dFJCcDVqU1V6WWRYRXdtNDBZem9zbENxZngyZ29pUUxPeHQyK0RBZ01CQUFFd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFBdDVhS2lQQVBTbmlTZzg1dDJNRitxekFETmthTC9CUWUyQlR3WDhNY0RrQTU4RFVwVERnK0phMnFYL3JYV255UXVtZmd3enJYWUhIRzhmMlJpdVRxT0RpMU9CQk1Wb1ZEejFnelhTVHZ4OVErM2VaVzUzYlhGaUF2OUNFejJLVHhHZlpzbStQUm1lOGZSRGZYc3cyUmtHTzU4WEZ2TXNnN3plVU1LTWtFZjFYU0Q4bU1EeXFITCtnQ1hBdFlJUjZBV2xKMzlSZW1hWldieHlCN1JzQU56OWl1V1ltbGpONmx6a0lwSHBmR3NVU1dNK0hxbVI2aG4vcW4ybUFxZTRLakE3NE42L2ZTUkZLOVZqTWIva0FFRllFaGhyL3kyam82Zi9md2FHYWVPb09NQUFjS1djVHVXZytDd2lIZVl4SFNIVUZ0NGpaODdIWkFjOUVPdm1LRkE9PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWxwOk5hbWVJRFBvbGljeSBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnRyYW5zaWVudCIgQWxsb3dDcmVhdGU9InRydWUiLz48L3NhbWxwOkF1dGhuUmVxdWVzdD4=",
					RelayState:  "gcH0iLEWgKzJM0rlyJZAhtn8xcY1i85ONmb-FfHwPWO4yIMZSZmUT6aV",
					Signature:   "",
					SigAlg:      "",
				},
				sp: sp{
					entityID: "http://localhost:8000/saml/metadata",
					metadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2023-04-08T08:29:26.467Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2023-04-08T08:29:26.467195Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQCHeEtdrUIg9DANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjMwNDA1MTUwOTA3WhcNMzMwNDAyMTUwOTA3WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7d1p0+WwoPtEofg+ZWO3m67ra6DQrAl9ImLvv8wYy2AAlsXlw0VhECWVoEXfeWBieuio00qt0gCBpbg+L0/Gk0QlTVqhwphUd2t94apDb86mXEAC16TiDr1EdfW26NUWtpQUK7VQu51Eja8LjZ8f2jyHOY1AQwqnKWsL1BEwaNfMK8MdiyrtslNfjKzi5xbvC+NA1L6wDKzHj+v2mGc/p4HKFjhs9ke4WtVVj6QjMZFSZrNUpdIZQh7+hPomZUp5/dGcYlqqcezwDXui1kHiOU7zbgpDngVdaadaNlTSkbTTLp6tRBp5jSUzYdXEwm40YzoslCqfx2goiQLOxt2+DAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAt5aKiPAPSniSg85t2MF+qzADNkaL/BQe2BTwX8McDkA58DUpTDg+Ja2qX/rXWnyQumfgwzrXYHHG8f2RiuTqODi1OBBMVoVDz1gzXSTvx9Q+3eZW53bXFiAv9CEz2KTxGfZsm+PRme8fRDfXsw2RkGO58XFvMsg7zeUMKMkEf1XSD8mMDyqHL+gCXAtYIR6AWlJ39RemaZWbxyB7RsANz9iuWYmljN6lzkIpHpfGsUSWM+HqmR6hn/qn2mAqe4KjA74N6/fSRFK9VjMb/kAEFYEhhr/y2jo6f/fwaGaeOoOMAAcKWcTuWg+CwiHeYxHSHUFt4jZ87HZAc9EOvmKFA=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQCHeEtdrUIg9DANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjMwNDA1MTUwOTA3WhcNMzMwNDAyMTUwOTA3WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7d1p0+WwoPtEofg+ZWO3m67ra6DQrAl9ImLvv8wYy2AAlsXlw0VhECWVoEXfeWBieuio00qt0gCBpbg+L0/Gk0QlTVqhwphUd2t94apDb86mXEAC16TiDr1EdfW26NUWtpQUK7VQu51Eja8LjZ8f2jyHOY1AQwqnKWsL1BEwaNfMK8MdiyrtslNfjKzi5xbvC+NA1L6wDKzHj+v2mGc/p4HKFjhs9ke4WtVVj6QjMZFSZrNUpdIZQh7+hPomZUp5/dGcYlqqcezwDXui1kHiOU7zbgpDngVdaadaNlTSkbTTLp6tRBp5jSUzYdXEwm40YzoslCqfx2goiQLOxt2+DAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAt5aKiPAPSniSg85t2MF+qzADNkaL/BQe2BTwX8McDkA58DUpTDg+Ja2qX/rXWnyQumfgwzrXYHHG8f2RiuTqODi1OBBMVoVDz1gzXSTvx9Q+3eZW53bXFiAv9CEz2KTxGfZsm+PRme8fRDfXsw2RkGO58XFvMsg7zeUMKMkEf1XSD8mMDyqHL+gCXAtYIR6AWlJ39RemaZWbxyB7RsANz9iuWYmljN6lzkIpHpfGsUSWM+HqmR6hn/qn2mAqe4KjA74N6/fSRFK9VjMb/kAEFYEhhr/y2jo6f/fwaGaeOoOMAAcKWcTuWg+CwiHeYxHSHUFt4jZ87HZAc9EOvmKFA=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
				},
			},
			res{
				code: 303,
				err:  false,
			}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := NewEndpoint(tt.args.metadataEndpoint)
			spInst, err := serviceprovider.NewServiceProvider(tt.args.sp.entityID, &serviceprovider.Config{Metadata: []byte(tt.args.sp.metadata)}, "")
			if err != nil {
				t.Errorf("error while creating service provider")
				return
			}

			mockStorage := idpStorageWithResponseCertAndSP(
				t,
				[]byte(tt.args.certificate),
				[]byte(tt.args.key),
				tt.args.sp.entityID,
				spInst,
				tt.args.sp.err,
				tt.args.request.ID,
			)
			if mockStorage == nil {
				t.Errorf("error while creating mockstorage")
				return
			}

			idp, err := NewIdentityProvider(endpoint, tt.args.config, mockStorage)
			if (err != nil) != tt.res.err {
				t.Errorf("NewIdentityProvider() error = %v", err.Error())
				return
			}
			if idp == nil {
				t.Errorf("error while creating idp")
				return
			}

			callURL := idp.endpoints.singleSignOnEndpoint.Relative()
			form := url.Values{}
			var req *http.Request
			if tt.args.request.Binding == RedirectBinding {
				callURL += "?SAMLRequest=" + tt.args.request.SAMLRequest
				if tt.args.request.RelayState != "" {
					callURL += "&RelayState=" + tt.args.request.RelayState
				}
				if tt.args.request.SigAlg != "" {
					callURL += "&SigAlg=" + tt.args.request.SigAlg
				}
				if tt.args.request.Signature != "" {
					callURL += "&Signature=" + tt.args.request.Signature
				}
				if tt.args.request.SAMLEncoding != "" {
					callURL += "&SAMLEncoding=" + tt.args.request.SAMLEncoding
				}
				req = httptest.NewRequest(http.MethodGet, callURL, nil)
			} else if tt.args.request.Binding == PostBinding {
				req = httptest.NewRequest(http.MethodPost, callURL, nil)
				form.Add("SAMLRequest", tt.args.request.SAMLRequest)
				form.Add("RelayState", tt.args.request.RelayState)
				req.Form = form
			}

			w := httptest.NewRecorder()
			callHandlerFuncWithIssuerInterceptor(tt.args.issuer, w, req, idp.ssoHandleFunc)

			res := w.Result()
			defer func() {
				_ = res.Body.Close()
			}()
			response, err := ioutil.ReadAll(res.Body)
			if res.StatusCode != tt.res.code {
				t.Errorf("ssoHandleFunc() code got = %v, want %v", res.StatusCode, tt.res)
				return
			}

			if tt.res.state != "" {
				if err := parseForState(string(response), tt.res.state); err != nil {
					t.Errorf("ssoHandleFunc() response state not: %v", tt.res.state)
					return
				}
			}
		})
	}
}

func parseForState(responseXML string, state string) error {
	response, err := xml.DecodeResponse("", responseXML)
	if err != nil {
		return err
	}

	if response.Status.StatusCode.Value != state {
		return fmt.Errorf("not expected status code")
	}
	return nil
}

func idpStorageWithResponseCertAndSP(
	t *testing.T,
	cert []byte,
	pKey []byte,
	entityID string,
	sp *serviceprovider.ServiceProvider,
	spErr error,
	authRequestID string,
) *mock.MockIDPStorage {
	mockStorage := idpStorageWithResponseCert(t, cert, pKey)
	mockStorage.EXPECT().GetEntityByID(gomock.Any(), entityID).Return(sp, spErr).MinTimes(0).MaxTimes(1)

	request := mock.NewMockAuthRequestInt(gomock.NewController(t))
	request.EXPECT().GetID().Return(authRequestID).MinTimes(0).MaxTimes(1)
	mockStorage.EXPECT().CreateAuthRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(request, nil).MinTimes(0).MaxTimes(1)

	return mockStorage
}
