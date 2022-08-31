package xml_test

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/zitadel/saml/pkg/provider/xml"
)

func Test_XmlReadMetadataFromURL(t *testing.T) {
	type res struct {
		metadata string
		err      bool
	}
	type args struct {
		metadata   string
		statusCode int
	}

	port := "8090"
	path := "/metadata"
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			name: "samltool IDP metadata",
			args: args{
				metadata:   "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-16T08:58:09Z\" cacheDuration=\"PT1650531489S\" entityID=\"http://localhot:" + port + "/metadata\" ID=\"pfx9d40c803-14bb-5465-a90e-34f413c0518d\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n  <ds:Reference URI=\"#pfx9d40c803-14bb-5465-a90e-34f413c0518d\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>Xr1IudSgJT2MIwytM/0TvsA5Gcw=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Y5jKD+dHnwJx8ChUWfKOBsfdonPVUrhq5Mdsa4OK3qnuv0cT3OCF5x/PUgOqDrrphjGfqa8XAwyj0hKVLUOlfnIwVMyL9QHghT7e72oz9Gzs+b4OOxDb/5z4U37J9WSxMzKkk85ezaf1TJ2ffEdJ4arTTd4ka1taXoU49mNMfChvOfaGhblt0rZSD3kUSbhk0Jy1P0HCim3+BqRWq/9UQrttdtL/UmzH/L9exKAuzLbpj88vpc64axbbOwUIpAW+2BE6uUbOU71AfOZ11SsJ91h6xXyk9fFF4yhE86W+Gghb7UiVWpo+vpL+Qxu4ISevfHZJ7WJ9FLopzaV0UPsUXw==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhot:" + port + "/saml/SLO\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhot:" + port + "/saml/SSO\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en-US\">ZITADEL</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en-US\">ZITADEL</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en-US\">https://zitadel.ch</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
				statusCode: http.StatusOK,
			},
			res: res{
				metadata: "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-16T08:58:09Z\" cacheDuration=\"PT1650531489S\" entityID=\"http://localhot:8090/metadata\" ID=\"pfx9d40c803-14bb-5465-a90e-34f413c0518d\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n  <ds:Reference URI=\"#pfx9d40c803-14bb-5465-a90e-34f413c0518d\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>Xr1IudSgJT2MIwytM/0TvsA5Gcw=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Y5jKD+dHnwJx8ChUWfKOBsfdonPVUrhq5Mdsa4OK3qnuv0cT3OCF5x/PUgOqDrrphjGfqa8XAwyj0hKVLUOlfnIwVMyL9QHghT7e72oz9Gzs+b4OOxDb/5z4U37J9WSxMzKkk85ezaf1TJ2ffEdJ4arTTd4ka1taXoU49mNMfChvOfaGhblt0rZSD3kUSbhk0Jy1P0HCim3+BqRWq/9UQrttdtL/UmzH/L9exKAuzLbpj88vpc64axbbOwUIpAW+2BE6uUbOU71AfOZ11SsJ91h6xXyk9fFF4yhE86W+Gghb7UiVWpo+vpL+Qxu4ISevfHZJ7WJ9FLopzaV0UPsUXw==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhot:8090/saml/SLO\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhot:8090/saml/SSO\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en-US\">ZITADEL</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en-US\">ZITADEL</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en-US\">https://zitadel.ch</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
				err:      false,
			},
		},
		{
			name: "samltool SP metadata",
			args: args{
				metadata:   "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-16T11:39:34Z\" cacheDuration=\"PT604800S\" entityID=\"http://localhost/metadata\" ID=\"pfx03a9fc7f-683d-d8b5-3feb-5b49ad8b512c\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n  <ds:Reference URI=\"#pfx03a9fc7f-683d-d8b5-3feb-5b49ad8b512c\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>DWf+E1YWP8w3xXa7dNS1n7AoDIk=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Hy7T5FLBSJbvzQDJ/+D61WOml3Fz1CYNpk/EbSLUmb++FQGyekk5TDAT0uwUFf1+FUdbPSqUGfgU462FED0gg//0hi0WnmI1Ljo7F2Rp1zUSyYk1BtzsXaib2KHrmtHvlbla6+I9vfSnIDbA/GgTgocmRSujnMVQtdgW5inpoUbddKaCZ0pE/0X2UbZ04a593c5B/P0q9i8FIIkPI9fkt9mwHss0wxDniy76MqES1imm/3utbLHZ7PffgO15CPSjSADIQzV3aBXOsH0dYOHJYACyPZ6XkDiV8Nq6H0z0O4TOQWLy2eSrz06IZ2tDMbb1qeOKJpgO5v9UjTLsv4GSHQ==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n    <md:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n        <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost/saml/slo\"/>\n        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n        <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost/saml/acs\" index=\"1\"/>\n        \n    </md:SPSSODescriptor>\n</md:EntityDescriptor>",
				statusCode: http.StatusOK,
			},
			res: res{
				metadata: "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-16T11:39:34Z\" cacheDuration=\"PT604800S\" entityID=\"http://localhost/metadata\" ID=\"pfx03a9fc7f-683d-d8b5-3feb-5b49ad8b512c\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n  <ds:Reference URI=\"#pfx03a9fc7f-683d-d8b5-3feb-5b49ad8b512c\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>DWf+E1YWP8w3xXa7dNS1n7AoDIk=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Hy7T5FLBSJbvzQDJ/+D61WOml3Fz1CYNpk/EbSLUmb++FQGyekk5TDAT0uwUFf1+FUdbPSqUGfgU462FED0gg//0hi0WnmI1Ljo7F2Rp1zUSyYk1BtzsXaib2KHrmtHvlbla6+I9vfSnIDbA/GgTgocmRSujnMVQtdgW5inpoUbddKaCZ0pE/0X2UbZ04a593c5B/P0q9i8FIIkPI9fkt9mwHss0wxDniy76MqES1imm/3utbLHZ7PffgO15CPSjSADIQzV3aBXOsH0dYOHJYACyPZ6XkDiV8Nq6H0z0O4TOQWLy2eSrz06IZ2tDMbb1qeOKJpgO5v9UjTLsv4GSHQ==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n    <md:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n        <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost/saml/slo\"/>\n        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n        <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost/saml/acs\" index=\"1\"/>\n        \n    </md:SPSSODescriptor>\n</md:EntityDescriptor>",
				err:      false,
			},
		},
		{
			name: "httpStatusCode 500",
			args: args{
				metadata:   "",
				statusCode: http.StatusInternalServerError,
			},
			res: res{
				metadata: "",
				err:      true,
			},
		},
		{
			name: "httpStatusCode 400",
			args: args{
				metadata:   "",
				statusCode: http.StatusBadRequest,
			},
			res: res{
				metadata: "",
				err:      true,
			},
		},
		{
			name: "httpStatusCode 403",
			args: args{
				metadata:   "",
				statusCode: http.StatusForbidden,
			},
			res: res{
				metadata: "",
				err:      true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(tt.args.statusCode, []byte(tt.args.metadata))

			data, err := xml.ReadMetadataFromURL(client, "http://localhost:"+port+path)
			if (err != nil) != tt.res.err {
				t.Error("ReadMetadataFromURL() failed to ReadMetadataFromURL")
				return
			}
			if string(data) != tt.res.metadata {
				t.Errorf("ReadMetadataFromURL() failed expected: %s, got: %s", tt.res.metadata, string(data))
				return
			}
		})
	}
}

func Test_XmlParseMetadataXmlIntoStruct(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		err  bool
	}{
		{
			name: "samltool IDP metadata",
			arg:  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-16T08:58:09Z\" cacheDuration=\"PT1650531489S\" entityID=\"http://localhot:8090/metadata\" ID=\"pfx9d40c803-14bb-5465-a90e-34f413c0518d\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n  <ds:Reference URI=\"#pfx9d40c803-14bb-5465-a90e-34f413c0518d\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>Xr1IudSgJT2MIwytM/0TvsA5Gcw=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Y5jKD+dHnwJx8ChUWfKOBsfdonPVUrhq5Mdsa4OK3qnuv0cT3OCF5x/PUgOqDrrphjGfqa8XAwyj0hKVLUOlfnIwVMyL9QHghT7e72oz9Gzs+b4OOxDb/5z4U37J9WSxMzKkk85ezaf1TJ2ffEdJ4arTTd4ka1taXoU49mNMfChvOfaGhblt0rZSD3kUSbhk0Jy1P0HCim3+BqRWq/9UQrttdtL/UmzH/L9exKAuzLbpj88vpc64axbbOwUIpAW+2BE6uUbOU71AfOZ11SsJ91h6xXyk9fFF4yhE86W+Gghb7UiVWpo+vpL+Qxu4ISevfHZJ7WJ9FLopzaV0UPsUXw==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhot:8090/saml/SLO\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhot:8090/saml/SSO\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en-US\">ZITADEL</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en-US\">ZITADEL</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en-US\">https://zitadel.ch</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
			err:  false,
		},
		{
			name: "samltool SP metadata",
			arg:  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2022-04-16T11:39:34Z\" cacheDuration=\"PT604800S\" entityID=\"http://localhost/metadata\" ID=\"pfx03a9fc7f-683d-d8b5-3feb-5b49ad8b512c\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n  <ds:Reference URI=\"#pfx03a9fc7f-683d-d8b5-3feb-5b49ad8b512c\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>DWf+E1YWP8w3xXa7dNS1n7AoDIk=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Hy7T5FLBSJbvzQDJ/+D61WOml3Fz1CYNpk/EbSLUmb++FQGyekk5TDAT0uwUFf1+FUdbPSqUGfgU462FED0gg//0hi0WnmI1Ljo7F2Rp1zUSyYk1BtzsXaib2KHrmtHvlbla6+I9vfSnIDbA/GgTgocmRSujnMVQtdgW5inpoUbddKaCZ0pE/0X2UbZ04a593c5B/P0q9i8FIIkPI9fkt9mwHss0wxDniy76MqES1imm/3utbLHZ7PffgO15CPSjSADIQzV3aBXOsH0dYOHJYACyPZ6XkDiV8Nq6H0z0O4TOQWLy2eSrz06IZ2tDMbb1qeOKJpgO5v9UjTLsv4GSHQ==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQwNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVoLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+ula1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4WsfawWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oaLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n    <md:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n        <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost/saml/slo\"/>\n        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n        <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost/saml/acs\" index=\"1\"/>\n        \n    </md:SPSSODescriptor>\n</md:EntityDescriptor>",
			err:  false,
		},
		{
			name: "unmarshall error",
			arg:  "unmarshall error",
			err:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entity, err := xml.ParseMetadataXmlIntoStruct([]byte(tt.arg))
			if (err != nil) != tt.err {
				t.Errorf("ParseMetadataXmlIntoStruct() failed expected: %v, got: %v", tt.err, err)
				return
			}
			if err == nil && entity == nil {
				t.Error("ParseMetadataXmlIntoStruct() failed as result equals nil")
				return
			}
		})
	}

}

type roundTripperFunc func(*http.Request) *http.Response

// RoundTrip implements the http.RoundTripper interface.
func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req), nil
}

// NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func newTestClient(httpStatus int, metadata []byte) *http.Client {
	fn := roundTripperFunc(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: httpStatus,
			Body:       ioutil.NopCloser(bytes.NewBuffer(metadata)),
			Header:     make(http.Header), //must be non-nil value
		}
	})
	return &http.Client{
		Transport: fn,
	}
}
