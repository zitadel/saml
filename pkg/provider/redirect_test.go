package provider

import (
	"testing"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml/md"
)

func TestRedirect_signatureRedirectVerificationNecessary(t *testing.T) {
	type args struct {
		sig         string
		binding     string
		idpMetadata *md.IDPSSODescriptorType
		spMetadata  *md.EntityDescriptorType
	}
	tests := []struct {
		name string
		args args
		res  bool
	}{
		{
			"redirect signature",
			args{
				sig:     "test",
				binding: RedirectBinding,
				spMetadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						AuthnRequestsSigned: "false",
					},
				},
				idpMetadata: &md.IDPSSODescriptorType{
					WantAuthnRequestsSigned: "false",
				},
			},
			true,
		},
		{
			"redirect AuthnRequestsSigned",
			args{
				sig:     "",
				binding: RedirectBinding,
				spMetadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						AuthnRequestsSigned: "true",
					},
				},
				idpMetadata: &md.IDPSSODescriptorType{
					WantAuthnRequestsSigned: "false",
				},
			},
			true,
		},
		{
			"redirect WantAuthnRequestsSigned",
			args{
				sig:     "",
				binding: RedirectBinding,
				spMetadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						AuthnRequestsSigned: "false",
					},
				},
				idpMetadata: &md.IDPSSODescriptorType{
					WantAuthnRequestsSigned: "true",
				},
			},
			true,
		},
		{
			"redirect no signature",
			args{
				sig:     "",
				binding: RedirectBinding,
				spMetadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						AuthnRequestsSigned: "false",
					},
				},
				idpMetadata: &md.IDPSSODescriptorType{
					WantAuthnRequestsSigned: "false",
				},
			},
			false,
		},
		{
			"post all required",
			args{
				sig:     "test",
				binding: PostBinding,
				spMetadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						AuthnRequestsSigned: "true",
					},
				},
				idpMetadata: &md.IDPSSODescriptorType{
					WantAuthnRequestsSigned: "true",
				},
			},
			false,
		},
		{
			"post nothing required",
			args{
				sig:     "",
				binding: PostBinding,
				spMetadata: &md.EntityDescriptorType{
					SPSSODescriptor: &md.SPSSODescriptorType{
						AuthnRequestsSigned: "false",
					},
				},
				idpMetadata: &md.IDPSSODescriptorType{
					WantAuthnRequestsSigned: "false",
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idpMetadataF := func() *md.IDPSSODescriptorType {
				return tt.args.idpMetadata
			}
			spMetadataF := func() *md.EntityDescriptorType {
				return tt.args.spMetadata
			}
			signatureF := func() string {
				return tt.args.sig
			}
			bindingF := func() string {
				return tt.args.binding
			}

			gotF := signatureRedirectVerificationNecessary(idpMetadataF, spMetadataF, signatureF, bindingF)
			got := gotF()
			if got != tt.res {
				t.Errorf("signatureRedirectVerificationNecessary() got = %v, want %v", got, tt.res)
			}
		})
	}
}

func TestRedirect_verifyRedirectSignature(t *testing.T) {
	type args struct {
		request    string
		relayState string
		sig        string
		sigAlg     string
		spMetadata string
	}
	tests := []struct {
		name string
		args args
		err  bool
	}{
		{
			"redirect signed request 1",
			args{
				request:    "nJJBj9MwEIX/ijX3No613WStTaSyFaLSwlabwoHb1JlQS45dPBNg/z1qu0iLhHLgas/nN+/53TOO4WTXkxzjM32fiEX9GkNke75oYMrRJmTPNuJIbMXZbv3x0ZqltshMWXyK8AY5zTOnnCS5FEBtNw34fjHcOHS35a0ZzHDo8XAwrrxb1VgPujZlP1RV3ddY3oH6Qpl9ig2YpQa1ZZ5oG1kwSgNGG7PQNwuj97qypbarellX1VdQG2LxEeVCHkVOtihCchiOicWutNamOO9ddN0TqPUfSw8p8jRS7ij/8I4+Pz/+g6611lcYHYPavXp752Pv47f5IA7XIbYf9vvdYvfU7aG9fIa9OMvqfcojyvwj55NzhpdRS1G8vEA7s+dIgj0K3hdvpNrXEnzCkbabXQrevfyHvGSM7CkKqHUI6edDJhRqQPJEULRXyb+r1v4OAAD//w==",
				relayState: "Hv9rftq0AHE47MealTo9m7TCIGhLVedUjmlwyCXLgUepny_c_WOO6f3e",
				sig:        "UE1buXT5lJvUMX5N1baY8OOvoOdsYplqiOdB8VYLUD3CfBt6EHlDta560bnKIovl5/xBsL8hZrMBwZXnzmZ5bNt9RYnSQZNxYXl5t/CnNScbdW4pC8I4gWzTxWmsKCQRBw9JvvpZCKojND1kKT0NMTlOPZHTB+Je8zbR2rNCkY4JePnmOIunOCXvfMpRgMScyFTe/udrLaBQPvVIZ7uE8noGzzANqHAOgS7HqvlLT4jBPd7RO3U/+Vp8mIUH+wkff9iZ/Kp9pambgQ18QJJNTb4By16JtHMqrziSAZX05YXXPyWhdontccZL/kOMHXY1VTaR8vABm/pOaX3GozZEPw==",
				sigAlg:     dsig.RSASHA1SignatureMethod,
				spMetadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967238Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
			},
			false,
		},
		{
			"redirect signed request 2",
			args{
				request:    "nJJBb9swDIX/isB7YkZt7FmoDWQNhgXo1qDOdtiNttlFgC1lIr2t/35I0gEZMOTQq8RPj+/p3QmNw8GtJt2HJ/4xsaj5PQ5B3PGigikFF0m8uEAji9PONatPD87O0ZEIJ/UxwAVyuM4cUtTYxQHMZl2B72fPXCDa8qZd3ra4RGoXZZE/9/liUWLe5/0iL7qibAnMV07iY6jAzhHMRmTiTRCloBVYtHaGtzOLOyyczd1NPs+X5Tcwaxb1gfRE7lUPLsuG2NGwj6JuiYg2O+6dNc0jmNVfS/cxyDRyajj99B1/eXr4D/0OEc8wdQJm++rtvQ+9D9+vB9Geh8R93O22s+1js4P69Bnu5CyZDzGNpNcfOZ4cMzyNOg7q9QXqK3uOrNST0l12IVW/luAzjbxZb+Pgu5c3yGuiIJ6DglkNQ/x1n5iUK9A0MWT1WfLfqtV/AgAA//8=",
				relayState: "YIz2twuwoPbPXS7oCd9ErSU9qsW2BvPC-STqeCN3EnJHoaUdG__bXIyD",
				sig:        "gnKrz9/UuY9te90EKQiiuOdFvuqszkDeFTDCPww21g301j39VKhMmCNdvnG6inW2W/I2lSFmu147QsIkIqZV55mYKAaQYuuSzcW9Ni0YZeshTNmBf72EUy3ykp58nzQScInTq2iRAUdwSDuL42ScSwOLh/UOvFH9cv6ERIBX9pljh89UbuLrL6cXbAlJofkiKorzGcTZfsATbWsSnAU0G9eBaGoSV2JMgRoLEpYq4J/wPN8fqB8htJ8fla+9BGrnBNGq3T92KvoEjANriMm+s50lko0ENa9KIbNPEh+45zEh/4t1MVIo1cZm82+Im2CT/rPp2s930DHvs4F2vOD8+A==",
				sigAlg:     dsig.RSASHA1SignatureMethod,
				spMetadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967238Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
			},
			false,
		},
		{
			"redirect signed request 3",
			args{
				request:    "nJJBj9MwEIX/ijX3NJbbpqm1iVS2QlRa2GpTOHCbOgO15NjFMwH236O2i7RIKIe92vP5ved5d4xDONvNKKf4RD9GYlG/hxDZXi4aGHO0CdmzjTgQW3G223x8sGamLTJTFp8ivELO08w5J0kuBVC7bQO+L+a1WRiqjTviqidz7N0a5z2tK1wtK1dXPerFaj6vQH2hzD7FBsxMg9oxj7SLLBilAaONKfSiMPqgV9bUdrGerZfVV1BbYvER5UqeRM62LENyGE6JxS611qa8+C677hHU5m+k+xR5HCh3lH96R5+fHv5D11rrG4yOQe1fsr3zsffx+/RHHG9DbD8cDvti/9gdoL0uw16TZfU+5QFl+pHLie+Lb9dRS1G8PEM74XMgwR4F78pXUu1LCT7hQLvtPgXvnt8gLxkje4oCahNC+nWfCYUakDwSlO1N8t+qtX8CAAD//w==",
				relayState: "iQURykBYIotpOOVTADzkn7WPmpT9DK3tujPKwYKbcVTj84Y4HXSIm2C2",
				sig:        "Kg1KLmUqSMVliymLBwUq09inVVHNx1UON86C3rmAyKXKj6q0av5qwlZova0htjpGqGcyZTEY4gJSM6FLN+bUjP4DVQul96jUr7+AFw4lMma2RrdzEINtzy8KXEHYbMxTTcDr0Mvnn3D7nmUi9inJNJmh4zJJafmQkhok4/DF0c7+AKizQCRIV35JCWf69XxhZFjMzijoKqWrkOSh9id14KktxSaHUyvVRH4LskzPsIuYeysL9xlrS77r3P8zuaU0EbaESwbTp/q/q7hEq6yH6vg1TXcJCIFPZOqTo0/00UAGie/ExmBp/OebvlHjgJP7g/bF6vK5kGFnxQi4To0Y1A==",
				sigAlg:     dsig.RSASHA1SignatureMethod,
				spMetadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967238Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
			},
			false,
		},
		{
			"redirect false signed request",
			args{
				request:    "nJJBj9MwEIX/ijX3NJbbpqm1iVS2QlRa2GpTOHCbOgO15NjFMwH236O2i7RIKIe92vP5ved5d4xDONvNKKf4RD9GYlG/hxDZXi4aGHO0CdmzjTgQW3G223x8sGamLTJTFp8ivELO08w5J0kuBVC7bQO+L+a1WRiqjTviqidz7N0a5z2tK1wtK1dXPerFaj6vQH2hzD7FBsxMg9oxj7SLLBilAaONKfSiMPqgV9bUdrGerZfVV1BbYvER5UqeRM62LENyGE6JxS611qa8+C677hHU5m+k+xR5HCh3lH96R5+fHv5D11rrG4yOQe1fsr3zsffx+/RHHG9DbD8cDvti/9gdoL0uw16TZfU+5QFl+pHLie+Lb9dRS1G8PEM74XMgwR4F78pXUu1LCT7hQLvtPgXvnt8gLxkje4oCahNC+nWfCYUakDwSlO1N8t+qtX8CAAD//w==",
				relayState: "iQURykBYIotpOOVTADzkn7WPmpT9DK3tujPKwYKbcVTj84Y4HXSIm2C2",
				sig:        "false signature",
				sigAlg:     dsig.RSASHA1SignatureMethod,
				spMetadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967238Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
			},
			true,
		},
		{
			"redirect signed request wrong relay state",
			args{
				request:    "nJJBj9MwEIX/ijX3NJbbpqm1iVS2QlRa2GpTOHCbOgO15NjFMwH236O2i7RIKIe92vP5ved5d4xDONvNKKf4RD9GYlG/hxDZXi4aGHO0CdmzjTgQW3G223x8sGamLTJTFp8ivELO08w5J0kuBVC7bQO+L+a1WRiqjTviqidz7N0a5z2tK1wtK1dXPerFaj6vQH2hzD7FBsxMg9oxj7SLLBilAaONKfSiMPqgV9bUdrGerZfVV1BbYvER5UqeRM62LENyGE6JxS611qa8+C677hHU5m+k+xR5HCh3lH96R5+fHv5D11rrG4yOQe1fsr3zsffx+/RHHG9DbD8cDvti/9gdoL0uw16TZfU+5QFl+pHLie+Lb9dRS1G8PEM74XMgwR4F78pXUu1LCT7hQLvtPgXvnt8gLxkje4oCahNC+nWfCYUakDwSlO1N8t+qtX8CAAD//w==",
				relayState: "wrong relaystate",
				sig:        "Kg1KLmUqSMVliymLBwUq09inVVHNx1UON86C3rmAyKXKj6q0av5qwlZova0htjpGqGcyZTEY4gJSM6FLN+bUjP4DVQul96jUr7+AFw4lMma2RrdzEINtzy8KXEHYbMxTTcDr0Mvnn3D7nmUi9inJNJmh4zJJafmQkhok4/DF0c7+AKizQCRIV35JCWf69XxhZFjMzijoKqWrkOSh9id14KktxSaHUyvVRH4LskzPsIuYeysL9xlrS77r3P8zuaU0EbaESwbTp/q/q7hEq6yH6vg1TXcJCIFPZOqTo0/00UAGie/ExmBp/OebvlHjgJP7g/bF6vK5kGFnxQi4To0Y1A==",
				sigAlg:     dsig.RSASHA1SignatureMethod,
				spMetadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967238Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
			},
			true,
		},
		{
			"redirect signed request wrong sigAlg",
			args{
				request:    "nJJBj9MwEIX/ijX3NJbbpqm1iVS2QlRa2GpTOHCbOgO15NjFMwH236O2i7RIKIe92vP5ved5d4xDONvNKKf4RD9GYlG/hxDZXi4aGHO0CdmzjTgQW3G223x8sGamLTJTFp8ivELO08w5J0kuBVC7bQO+L+a1WRiqjTviqidz7N0a5z2tK1wtK1dXPerFaj6vQH2hzD7FBsxMg9oxj7SLLBilAaONKfSiMPqgV9bUdrGerZfVV1BbYvER5UqeRM62LENyGE6JxS611qa8+C677hHU5m+k+xR5HCh3lH96R5+fHv5D11rrG4yOQe1fsr3zsffx+/RHHG9DbD8cDvti/9gdoL0uw16TZfU+5QFl+pHLie+Lb9dRS1G8PEM74XMgwR4F78pXUu1LCT7hQLvtPgXvnt8gLxkje4oCahNC+nWfCYUakDwSlO1N8t+qtX8CAAD//w==",
				relayState: "iQURykBYIotpOOVTADzkn7WPmpT9DK3tujPKwYKbcVTj84Y4HXSIm2C2",
				sig:        "Kg1KLmUqSMVliymLBwUq09inVVHNx1UON86C3rmAyKXKj6q0av5qwlZova0htjpGqGcyZTEY4gJSM6FLN+bUjP4DVQul96jUr7+AFw4lMma2RrdzEINtzy8KXEHYbMxTTcDr0Mvnn3D7nmUi9inJNJmh4zJJafmQkhok4/DF0c7+AKizQCRIV35JCWf69XxhZFjMzijoKqWrkOSh9id14KktxSaHUyvVRH4LskzPsIuYeysL9xlrS77r3P8zuaU0EbaESwbTp/q/q7hEq6yH6vg1TXcJCIFPZOqTo0/00UAGie/ExmBp/OebvlHjgJP7g/bF6vK5kGFnxQi4To0Y1A==",
				sigAlg:     dsig.RSASHA256SignatureMethod,
				spMetadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967238Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
			},
			true,
		},
		{
			"redirect signed request request changed",
			args{
				request:    "changed",
				relayState: "iQURykBYIotpOOVTADzkn7WPmpT9DK3tujPKwYKbcVTj84Y4HXSIm2C2",
				sig:        "Kg1KLmUqSMVliymLBwUq09inVVHNx1UON86C3rmAyKXKj6q0av5qwlZova0htjpGqGcyZTEY4gJSM6FLN+bUjP4DVQul96jUr7+AFw4lMma2RrdzEINtzy8KXEHYbMxTTcDr0Mvnn3D7nmUi9inJNJmh4zJJafmQkhok4/DF0c7+AKizQCRIV35JCWf69XxhZFjMzijoKqWrkOSh9id14KktxSaHUyvVRH4LskzPsIuYeysL9xlrS77r3P8zuaU0EbaESwbTp/q/q7hEq6yH6vg1TXcJCIFPZOqTo0/00UAGie/ExmBp/OebvlHjgJP7g/bF6vK5kGFnxQi4To0Y1A==",
				sigAlg:     dsig.RSASHA1SignatureMethod,
				spMetadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967238Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
			},
			true,
		},
		{
			"redirect no request",
			args{
				request:    "",
				relayState: "Hv9rftq0AHE47MealTo9m7TCIGhLVedUjmlwyCXLgUepny_c_WOO6f3e",
				sig:        "UE1buXT5lJvUMX5N1baY8OOvoOdsYplqiOdB8VYLUD3CfBt6EHlDta560bnKIovl5/xBsL8hZrMBwZXnzmZ5bNt9RYnSQZNxYXl5t/CnNScbdW4pC8I4gWzTxWmsKCQRBw9JvvpZCKojND1kKT0NMTlOPZHTB+Je8zbR2rNCkY4JePnmOIunOCXvfMpRgMScyFTe/udrLaBQPvVIZ7uE8noGzzANqHAOgS7HqvlLT4jBPd7RO3U/+Vp8mIUH+wkff9iZ/Kp9pambgQ18QJJNTb4By16JtHMqrziSAZX05YXXPyWhdontccZL/kOMHXY1VTaR8vABm/pOaX3GozZEPw==",
				sigAlg:     dsig.RSASHA1SignatureMethod,
				spMetadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967238Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
			},
			true,
		},
		{
			"redirect no relayState",
			args{
				request:    "nJJBj9MwEIX/ijX3No613WStTaSyFaLSwlabwoHb1JlQS45dPBNg/z1qu0iLhHLgas/nN+/53TOO4WTXkxzjM32fiEX9GkNke75oYMrRJmTPNuJIbMXZbv3x0ZqltshMWXyK8AY5zTOnnCS5FEBtNw34fjHcOHS35a0ZzHDo8XAwrrxb1VgPujZlP1RV3ddY3oH6Qpl9ig2YpQa1ZZ5oG1kwSgNGG7PQNwuj97qypbarellX1VdQG2LxEeVCHkVOtihCchiOicWutNamOO9ddN0TqPUfSw8p8jRS7ij/8I4+Pz/+g6611lcYHYPavXp752Pv47f5IA7XIbYf9vvdYvfU7aG9fIa9OMvqfcojyvwj55NzhpdRS1G8vEA7s+dIgj0K3hdvpNrXEnzCkbabXQrevfyHvGSM7CkKqHUI6edDJhRqQPJEULRXyb+r1v4OAAD//w==",
				relayState: "",
				sig:        "UE1buXT5lJvUMX5N1baY8OOvoOdsYplqiOdB8VYLUD3CfBt6EHlDta560bnKIovl5/xBsL8hZrMBwZXnzmZ5bNt9RYnSQZNxYXl5t/CnNScbdW4pC8I4gWzTxWmsKCQRBw9JvvpZCKojND1kKT0NMTlOPZHTB+Je8zbR2rNCkY4JePnmOIunOCXvfMpRgMScyFTe/udrLaBQPvVIZ7uE8noGzzANqHAOgS7HqvlLT4jBPd7RO3U/+Vp8mIUH+wkff9iZ/Kp9pambgQ18QJJNTb4By16JtHMqrziSAZX05YXXPyWhdontccZL/kOMHXY1VTaR8vABm/pOaX3GozZEPw==",
				sigAlg:     dsig.RSASHA1SignatureMethod,
				spMetadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967238Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
			},
			true,
		},
		{
			"redirect no sigAlg",
			args{
				request:    "nJJBj9MwEIX/ijX3No613WStTaSyFaLSwlabwoHb1JlQS45dPBNg/z1qu0iLhHLgas/nN+/53TOO4WTXkxzjM32fiEX9GkNke75oYMrRJmTPNuJIbMXZbv3x0ZqltshMWXyK8AY5zTOnnCS5FEBtNw34fjHcOHS35a0ZzHDo8XAwrrxb1VgPujZlP1RV3ddY3oH6Qpl9ig2YpQa1ZZ5oG1kwSgNGG7PQNwuj97qypbarellX1VdQG2LxEeVCHkVOtihCchiOicWutNamOO9ddN0TqPUfSw8p8jRS7ij/8I4+Pz/+g6611lcYHYPavXp752Pv47f5IA7XIbYf9vvdYvfU7aG9fIa9OMvqfcojyvwj55NzhpdRS1G8vEA7s+dIgj0K3hdvpNrXEnzCkbabXQrevfyHvGSM7CkKqHUI6edDJhRqQPJEULRXyb+r1v4OAAD//w==",
				relayState: "Hv9rftq0AHE47MealTo9m7TCIGhLVedUjmlwyCXLgUepny_c_WOO6f3e",
				sig:        "UE1buXT5lJvUMX5N1baY8OOvoOdsYplqiOdB8VYLUD3CfBt6EHlDta560bnKIovl5/xBsL8hZrMBwZXnzmZ5bNt9RYnSQZNxYXl5t/CnNScbdW4pC8I4gWzTxWmsKCQRBw9JvvpZCKojND1kKT0NMTlOPZHTB+Je8zbR2rNCkY4JePnmOIunOCXvfMpRgMScyFTe/udrLaBQPvVIZ7uE8noGzzANqHAOgS7HqvlLT4jBPd7RO3U/+Vp8mIUH+wkff9iZ/Kp9pambgQ18QJJNTb4By16JtHMqrziSAZX05YXXPyWhdontccZL/kOMHXY1VTaR8vABm/pOaX3GozZEPw==",
				sigAlg:     "",
				spMetadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967238Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
			},
			true,
		},
		{
			"redirect no sig",
			args{
				request:    "nJJBj9MwEIX/ijX3No613WStTaSyFaLSwlabwoHb1JlQS45dPBNg/z1qu0iLhHLgas/nN+/53TOO4WTXkxzjM32fiEX9GkNke75oYMrRJmTPNuJIbMXZbv3x0ZqltshMWXyK8AY5zTOnnCS5FEBtNw34fjHcOHS35a0ZzHDo8XAwrrxb1VgPujZlP1RV3ddY3oH6Qpl9ig2YpQa1ZZ5oG1kwSgNGG7PQNwuj97qypbarellX1VdQG2LxEeVCHkVOtihCchiOicWutNamOO9ddN0TqPUfSw8p8jRS7ij/8I4+Pz/+g6611lcYHYPavXp752Pv47f5IA7XIbYf9vvdYvfU7aG9fIa9OMvqfcojyvwj55NzhpdRS1G8vEA7s+dIgj0K3hdvpNrXEnzCkbabXQrevfyHvGSM7CkKqHUI6edDJhRqQPJEULRXyb+r1v4OAAD//w==",
				relayState: "Hv9rftq0AHE47MealTo9m7TCIGhLVedUjmlwyCXLgUepny_c_WOO6f3e",
				sig:        "",
				sigAlg:     dsig.RSASHA1SignatureMethod,
				spMetadata: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967Z\" entityID=\"http://localhost:8000/saml/metadata\">\n  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-10T13:51:05.967238Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n    <KeyDescriptor use=\"encryption\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n    </KeyDescriptor>\n    <KeyDescriptor use=\"signing\">\n      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n        <X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n          <X509Certificate xmlns=\"http://www.w3.org/2000/09/xmldsig#\">MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</X509Certificate>\n        </X509Data>\n      </KeyInfo>\n    </KeyDescriptor>\n    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/slo\" ResponseLocation=\"http://localhost:8000/saml/slo\"></SingleLogoutService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8000/saml/acs\" index=\"1\"></AssertionConsumerService>\n    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8000/saml/acs\" index=\"2\"></AssertionConsumerService>\n  </SPSSODescriptor>\n</EntityDescriptor>",
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spConfig := &serviceprovider.Config{Metadata: []byte(tt.args.spMetadata)}

			sp, err := serviceprovider.NewServiceProvider("test", spConfig, func(s string) string { return "" })
			if err != nil {
				t.Errorf("verifyRedirectSignature() got = %v, wanted to create service provider instance", err)
				return
			}

			requestF := func() string {
				return tt.args.request
			}
			relayStateF := func() string {
				return tt.args.relayState
			}
			sigF := func() string {
				return tt.args.sig
			}
			sigAlgF := func() string {
				return tt.args.sigAlg
			}
			spF := func() *serviceprovider.ServiceProvider {
				return sp
			}
			errF := func(err error) {
				if (err != nil) != tt.err {
					t.Errorf("verifyRedirectSignature() got = %v, want %v", err, tt.err)
				}
			}

			gotF := verifyRedirectSignature(requestF, relayStateF, sigF, sigAlgF, spF, errF)
			got := gotF()
			if (got != nil) != tt.err {
				t.Errorf("verifyRedirectSignature() got = %v, want %v", got, tt.err)
				return
			}
		})
	}
}

func TestRedirect_buildRedirectQuery(t *testing.T) {
	type args struct {
		response   string
		relayState string
		sigAlg     string
		sig        string
	}
	tests := []struct {
		name string
		args args
		res  string
	}{
		{
			"full",
			args{
				"response",
				"relayState",
				"sigAlg",
				"sig",
			},
			"SAMLResponse=response&RelayState=relayState&Signature=sig&SigAlg=sigAlg",
		},
		{
			"full escaped",
			args{
				"response!",
				"relayState!",
				"sigAlg!",
				"sig!",
			},
			"SAMLResponse=response%21&RelayState=relayState%21&Signature=sig%21&SigAlg=sigAlg%21",
		},
		{
			"only response",
			args{
				"response!",
				"",
				"",
				"",
			},
			"SAMLResponse=response%21",
		},
		{
			"response relaystate",
			args{
				"response!",
				"relayState!",
				"",
				"",
			},
			"SAMLResponse=response%21&RelayState=relayState%21",
		},
		{
			"response relaystate sigalg",
			args{
				"response!",
				"relayState!",
				"sigAlg!",
				"",
			},
			"SAMLResponse=response%21&RelayState=relayState%21&SigAlg=sigAlg%21",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildRedirectQuery(tt.args.response, tt.args.relayState, tt.args.sigAlg, tt.args.sig)
			if got != tt.res {
				t.Errorf("verifyRedirectSignature() got = %v, want %v", got, tt.res)
				return
			}
		})
	}
}
