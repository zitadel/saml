package provider

import (
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

func TestLogout_logoutHandleFunc(t *testing.T) {
	type res struct {
		code  int
		state string
	}
	tests := []struct {
		name        string
		samlRequest string
		sp          bool
		res         res
	}{
		{
			name: "request without NameID",
			sp:   true,
			samlRequest: base64.StdEncoding.EncodeToString([]byte(compactXML(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-no-nameid" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="http://localhost:50002/saml/SLO">
				<saml:Issuer>http://localhost:8000/saml/metadata</saml:Issuer>
			</samlp:LogoutRequest>`))),
			res: res{
				code:  200,
				state: StatusCodeSuccess,
			},
		},
		{
			name: "request without issuer",
			samlRequest: base64.StdEncoding.EncodeToString([]byte(compactXML(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-no-issuer" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="http://localhost:50002/saml/SLO">
			</samlp:LogoutRequest>`))),
			res: res{
				code:  200,
				state: StatusCodeRequestDenied,
			},
		},
		{
			name: "request with empty issuer",
			samlRequest: base64.StdEncoding.EncodeToString([]byte(compactXML(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-empty-issuer" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="http://localhost:50002/saml/SLO">
				<saml:Issuer></saml:Issuer>
			</samlp:LogoutRequest>`))),
			res: res{
				code:  200,
				state: StatusCodeRequestDenied,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &IdentityProviderConfig{
				SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
				MetadataIDPConfig:  &MetadataIDPConfig{},
				Endpoints: &EndpointConfig{
					SingleLogOut: getEndpointPointer("/saml/SLO", "http://localhost:50002/saml/SLO"),
				},
			}
			mockStorage := idpStorageWithResponseCert(t, []byte(""), []byte(""))

			if tt.sp {
				entityID := "http://localhost:8000/saml/metadata"
				metadata := compactXML(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:8000/saml/metadata">
				  <SPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="true">
				    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8000/saml/acs" index="1"/>
				  </SPSSODescriptor>
				</EntityDescriptor>`)
				spInst, err := serviceprovider.NewServiceProvider(entityID, &serviceprovider.Config{Metadata: []byte(metadata)}, func(s string) string { return "" })
				if err != nil {
					t.Fatalf("error while creating service provider: %v", err)
				}
				mockStorage.EXPECT().GetEntityByID(gomock.Any(), entityID).Return(spInst, nil).Times(1)
			}

			idp, err := newTestIdentityProvider(NewEndpoint("/saml/metadata"), config, mockStorage)
			if err != nil {
				t.Fatalf("NewIdentityProvider() error = %v", err)
			}

			form := url.Values{}
			form.Add("SAMLRequest", tt.samlRequest)
			req := httptest.NewRequest(http.MethodPost, idp.endpoints.singleLogoutEndpoint.Relative(), nil)
			req.Form = form

			w := httptest.NewRecorder()
			callHandlerFuncWithIssuerInterceptor("http://localhost:50002", w, req, idp.logoutHandleFunc)

			result := w.Result()
			defer func() { _ = result.Body.Close() }()
			body, err := io.ReadAll(result.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}
			if result.StatusCode != tt.res.code {
				t.Fatalf("logoutHandleFunc() code got = %v, want %v", result.StatusCode, tt.res.code)
			}

			response := &samlp.LogoutResponseType{}
			if err := xml.Unmarshal(body, response); err != nil {
				t.Fatalf("failed to decode logout response: %v", err)
			}
			if response.Status.StatusCode.Value != tt.res.state {
				t.Errorf("logoutHandleFunc() status got = %v, want %v", response.Status.StatusCode.Value, tt.res.state)
			}
		})
	}
}
