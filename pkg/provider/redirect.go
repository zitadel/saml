package provider

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/signature"
	"github.com/zitadel/saml/pkg/provider/xml"
	"github.com/zitadel/saml/pkg/provider/xml/md"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

func signatureRedirectVerificationNecessary(
	idpMetadataF func() *md.IDPSSODescriptorType,
	spMetadataF func() *md.EntityDescriptorType,
	signatureF func() string,
	protocolBinding func() string,
) func() bool {
	return func() bool {
		spMeta := spMetadataF()
		idpMeta := idpMetadataF()

		return ((spMeta == nil || spMeta.SPSSODescriptor == nil || spMeta.SPSSODescriptor.AuthnRequestsSigned == "true") ||
			(idpMeta == nil || idpMeta.WantAuthnRequestsSigned == "true") ||
			signatureF() != "") &&
			protocolBinding() == RedirectBinding
	}
}

func verifyRedirectSignature(
	authRequest func() string,
	relayState func() string,
	sig func() string,
	sigAlg func() string,
	sp func() *serviceprovider.ServiceProvider,
	errF func(error),
) func() error {
	return func() error {
		if authRequest() == "" {
			return fmt.Errorf("no authrequest provided but required")
		}
		if sig() == "" {
			return fmt.Errorf("no signature provided but required")
		}
		if sigAlg() == "" {
			return fmt.Errorf("no signature algorithm provided but required")
		}

		spInstance := sp()
		if sp == nil {
			return fmt.Errorf("no service provider instance provided but required")
		}

		err := spInstance.ValidateRedirectSignature(
			authRequest(),
			relayState(),
			sigAlg(),
			sig(),
		)
		errF(err)
		return err
	}
}

func createRedirectSignature(
	samlResponse *samlp.ResponseType,
	key *rsa.PrivateKey,
	cert []byte,
	signatureAlgorithm string,
	relayState string,
) (string, string, error) {
	resp, err := xml.Marshal(samlResponse)
	if err != nil {
		return "", "", err
	}

	respData, err := xml.DeflateAndBase64(resp)
	if err != nil {
		return "", "", err
	}

	tlsCert, err := signature.ParseTlsKeyPair(cert, key)
	if err != nil {
		return "", "", err
	}

	signingContext, err := signature.GetSigningContext(tlsCert, signatureAlgorithm)
	if err != nil {
		return "", "", err
	}

	sig, err := signature.CreateRedirect(signingContext, BuildRedirectQuery(string(respData), relayState, signatureAlgorithm, ""))
	if err != nil {
		return "", "", err
	}

	return url.QueryEscape(base64.StdEncoding.EncodeToString(sig)), url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(signatureAlgorithm))), nil
}

func BuildRedirectQuery(
	response string,
	relayState string,
	sigAlg string,
	sig string,
) string {
	query := "SAMLResponse=" + url.QueryEscape(response)
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	if sig != "" {
		query += "&Signature=" + url.QueryEscape(sig)
	}
	if sigAlg != "" {
		query += "&SigAlg=" + url.QueryEscape(sigAlg)
	}

	return query
}
