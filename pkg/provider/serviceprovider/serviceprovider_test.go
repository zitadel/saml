package serviceprovider_test

import (
	"testing"

	"github.com/zitadel/saml/pkg/provider/serviceprovider"
)

func TestNewServiceProvider(t *testing.T) {
	tests := []struct {
		name     string
		metadata string
		err      bool
	}{
		{
			name: "metadata with SPSSODescriptor",
			metadata: `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:8000/saml/metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8000/saml/acs" index="1"></AssertionConsumerService>
  </SPSSODescriptor>
</EntityDescriptor>`,
			err: false,
		},
		{
			name: "metadata without SPSSODescriptor",
			metadata: `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:8000/saml/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:8000/saml/sso"></SingleSignOnService>
  </IDPSSODescriptor>
</EntityDescriptor>`,
			err: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp, err := serviceprovider.NewServiceProvider(
				"id",
				&serviceprovider.Config{Metadata: []byte(tt.metadata)},
				func(string) string { return "" },
			)
			if (err != nil) != tt.err {
				t.Errorf("NewServiceProvider() error = %v, want error %v", err, tt.err)
				return
			}
			if tt.err {
				return
			}
			if sp == nil {
				t.Error("NewServiceProvider() returned no service provider")
			}
		})
	}
}
