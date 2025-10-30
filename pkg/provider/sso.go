package provider

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/zitadel/logging"

	"github.com/zitadel/saml/pkg/provider/checker"
	"github.com/zitadel/saml/pkg/provider/models"
	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	"github.com/zitadel/saml/pkg/provider/xml"
	"github.com/zitadel/saml/pkg/provider/xml/md"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
	"github.com/zitadel/saml/pkg/provider/xml/xml_dsig"
)

type AuthRequestForm struct {
	AuthRequest string
	Encoding    string
	RelayState  string
	SigAlg      string
	Sig         string
	Binding     string
}

func (p *IdentityProvider) ssoHandleFunc(w http.ResponseWriter, r *http.Request) {
	checkerInstance := checker.Checker{}
	var authRequestForm *AuthRequestForm
	var authNRequest *samlp.AuthnRequestType
	var sp *serviceprovider.ServiceProvider
	var authRequest models.AuthRequestInt
	var err error
	var acsIndex *int

	response := &Response{
		PostTemplate: p.postTemplate,
		ErrorFunc: func(err error) {
			http.Error(w, fmt.Errorf("failed to send response: %w", err).Error(), http.StatusInternalServerError)
		},
		Issuer: p.GetEntityID(r.Context()),
	}

	metadata, _, err := p.GetMetadata(r.Context())
	if err != nil {
		err := fmt.Errorf("failed to read idp metadata: %w", err)
		logging.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// parse form to cover POST and REDIRECT binding
	checkerInstance.WithLogicStep(
		func() error {
			authRequestForm, err = getAuthRequestFromRequest(r)
			if err != nil {
				return err
			}
			response.SigAlg = authRequestForm.SigAlg
			response.RelayState = authRequestForm.RelayState
			return nil
		},
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeRequestDenied, fmt.Errorf("failed to parse form").Error(), p.TimeFormat))
		},
	)

	// verify that request is not empty
	checkerInstance.WithValueNotEmptyCheck(
		"SAMLRequest",
		func() string { return authRequestForm.AuthRequest },
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeRequestDenied, fmt.Errorf("no auth request provided").Error(), p.TimeFormat))
		},
	)

	// verify that there is a signature provided if signature algorithm is provided
	checkerInstance.WithConditionalValueNotEmpty(
		func() bool { return authRequestForm.SigAlg != "" },
		"Signature",
		func() string { return authRequestForm.Sig },
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeRequestDenied, fmt.Errorf("signature algorith provided but no signature").Error(), p.TimeFormat))
		},
	)

	// decode request from xml into golang struct
	checkerInstance.WithLogicStep(
		func() error {
			authNRequest, err = xml.DecodeAuthNRequest(authRequestForm.Encoding, authRequestForm.AuthRequest)
			if err != nil {
				return err
			}
			response.RequestID = authNRequest.Id
			return nil
		},
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeRequestDenied, fmt.Errorf("failed to decode request").Error(), p.TimeFormat))
		},
	)

	// get persisted service provider from issuer out of the request
	checkerInstance.WithLogicStep(
		func() error {
			sp, err = p.GetServiceProvider(r.Context(), authNRequest.Issuer.Text)
			if err != nil {
				return err
			}
			response.Audience = sp.GetEntityID()
			return nil
		},
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeRequestDenied, fmt.Errorf("failed to find registered serviceprovider: %w", err).Error(), p.TimeFormat))
		},
	)

	//validate used certificate for signing the request
	checkerInstance.WithConditionalLogicStep(
		certificateCheckNecessary(
			func() *xml_dsig.SignatureType { return authNRequest.Signature },
			func() *md.EntityDescriptorType { return sp.Metadata },
		),
		checkCertificate(
			func() *xml_dsig.SignatureType { return authNRequest.Signature },
			func() *md.EntityDescriptorType { return sp.Metadata },
		),
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeRequestDenied, fmt.Errorf("failed to validate certificate from request: %w", err).Error(), p.TimeFormat))
		},
	)

	// verify signature if necessary
	checkerInstance.WithConditionalLogicStep(
		signatureRedirectVerificationNecessary(
			func() *md.IDPSSODescriptorType { return metadata },
			func() *md.EntityDescriptorType { return sp.Metadata },
			func() string { return authRequestForm.Sig },
			func() string { return authRequestForm.Binding },
		),
		verifyRedirectSignature(
			func() string { return authRequestForm.AuthRequest },
			func() string { return authRequestForm.RelayState },
			func() string { return authRequestForm.Sig },
			func() string { return authRequestForm.SigAlg },
			func() *serviceprovider.ServiceProvider { return sp },
			func(errF error) { err = errF },
		),
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeRequestDenied, fmt.Errorf("failed to verify signature: %w", err).Error(), p.TimeFormat))
		},
	)

	// verify signature if necessary
	checkerInstance.WithConditionalLogicStep(
		signaturePostVerificationNecessary(
			func() *md.IDPSSODescriptorType { return metadata },
			func() *md.EntityDescriptorType { return sp.Metadata },
			func() *xml_dsig.SignatureType { return authNRequest.Signature },
			func() string { return authRequestForm.Binding },
		),
		verifyPostSignature(
			func() string { return authRequestForm.AuthRequest },
			func() *serviceprovider.ServiceProvider { return sp },
			func(errF error) { err = errF },
		),
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeRequestDenied, fmt.Errorf("failed to verify signature: %w", err).Error(), p.TimeFormat))
		},
	)

	// work out used acs url and protocolbinding for response
	checkerInstance.WithValueStep(
		func() {
			if authNRequest.AssertionConsumerServiceIndex != "" {
				if i, err := strconv.Atoi(authNRequest.AssertionConsumerServiceIndex); err == nil {
					acsIndex = &i
				}
			}

			response.AcsUrl, response.ProtocolBinding = GetAcsUrlAndBindingForResponse(
				sp.Metadata.SPSSODescriptor.AssertionConsumerService,
				authNRequest.ProtocolBinding,
				authNRequest.AssertionConsumerServiceURL,
				acsIndex,
			)
		},
	)

	// check if supported acs url is provided
	checkerInstance.WithValueNotEmptyCheck(
		"acsUrl",
		func() string { return response.AcsUrl },
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeUnsupportedBinding, fmt.Errorf("missing usable assertion consumer url").Error(), p.TimeFormat))
		},
	)

	// check if supported protocolbinding is provided
	checkerInstance.WithValueNotEmptyCheck(
		"protocol binding",
		func() string { return response.ProtocolBinding },
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeUnsupportedBinding, fmt.Errorf("missing usable protocol binding").Error(), p.TimeFormat))
		},
	)

	checkerInstance.WithLogicStep(
		checkRequestRequiredContent(
			func() *md.IDPSSODescriptorType { return metadata },
			func() *serviceprovider.ServiceProvider { return sp },
			func() *samlp.AuthnRequestType { return authNRequest },
		),
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeRequestDenied, fmt.Errorf("failed to validate request content: %w", err).Error(), p.TimeFormat))
		},
	)

	// persist authrequest
	checkerInstance.WithLogicStep(
		func() error {
			authRequest, err = p.storage.CreateAuthRequest(
				r.Context(),
				authNRequest,
				response.AcsUrl,
				response.ProtocolBinding,
				authRequestForm.RelayState,
				sp.ID,
			)
			return err
		},
		func() {
			response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeResponder, fmt.Errorf("failed to persist request: %w", err).Error(), p.TimeFormat))
		},
	)

	//check and log errors if necessary
	if checkerInstance.CheckFailed() {
		return
	}

	switch response.ProtocolBinding {
	case RedirectBinding, PostBinding:
		http.Redirect(w, r, sp.LoginURL(authRequest.GetID()), http.StatusSeeOther)
	default:
		logging.Error(err)
		response.sendBackResponse(r, w, response.makeFailedResponse(StatusCodeUnsupportedBinding, fmt.Errorf("unsupported binding: %s", response.ProtocolBinding).Error(), p.TimeFormat))
	}
	return
}

func getAuthRequestFromRequest(r *http.Request) (*AuthRequestForm, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, fmt.Errorf("failed to parse form: %w", err)
	}

	binding := ""
	if _, ok := r.URL.Query()["SAMLRequest"]; ok {
		binding = RedirectBinding
	} else {
		binding = PostBinding
	}

	request := &AuthRequestForm{
		AuthRequest: r.FormValue("SAMLRequest"),
		Encoding:    r.FormValue("SAMLEncoding"),
		RelayState:  r.FormValue("RelayState"),
		SigAlg:      r.FormValue("SigAlg"),
		Sig:         r.FormValue("Signature"),
		Binding:     binding,
	}
	if request.Encoding == "" && binding == RedirectBinding {
		request.Encoding = xml.EncodingDeflate
	}

	return request, nil
}

func checkRequestRequiredContent(
	idpMetadataF func() *md.IDPSSODescriptorType,
	spF func() *serviceprovider.ServiceProvider,
	authNRequestF func() *samlp.AuthnRequestType,
) func() error {
	return func() error {
		sp := spF()
		idpMetadata := idpMetadataF()
		authNRequest := authNRequestF()

		if authNRequest.Conditions != nil &&
			(authNRequest.Conditions.NotOnOrAfter != "" || authNRequest.Conditions.NotBefore != "") {
			if err := checkIfRequestTimeIsStillValid(
				func() string { return authNRequest.Conditions.NotBefore },
				func() string { return authNRequest.Conditions.NotOnOrAfter },
				DefaultTimeFormat,
			)(); err != nil {
				return err
			}
		}

		if authNRequest.Id == "" {
			return fmt.Errorf("ID is missing in request")
		}

		if authNRequest.Version == "" {
			return fmt.Errorf("version is missing in request")
		}

		if authNRequest.Issuer.Text == "" {
			return fmt.Errorf("issuer is missing in request")
		}

		if authNRequest.Issuer.Text != sp.GetEntityID() {
			return fmt.Errorf("issuer in request not equal entityID of service provider")
		}

		if err := verifyRequestDestinationOfAuthRequest(idpMetadata, authNRequest); err != nil {
			return err
		}

		return nil
	}
}

func certificateCheckNecessary(
	authRequestSignatureF func() *xml_dsig.SignatureType,
	spMetadataF func() *md.EntityDescriptorType,
) func() bool {
	return func() bool {
		sig := authRequestSignatureF()
		spMetadata := spMetadataF()
		return sig != nil && sig.KeyInfo != nil &&
			spMetadata != nil && spMetadata.SPSSODescriptor != nil &&
			spMetadata.SPSSODescriptor.KeyDescriptor != nil && len(spMetadata.SPSSODescriptor.KeyDescriptor) > 0
	}
}

func checkCertificate(
	authRequestSignatureF func() *xml_dsig.SignatureType,
	spMetadataF func() *md.EntityDescriptorType,
) func() error {
	return func() error {
		metadata := spMetadataF()
		request := authRequestSignatureF()
		if metadata == nil || metadata.SPSSODescriptor == nil || metadata.SPSSODescriptor.KeyDescriptor == nil || len(metadata.SPSSODescriptor.KeyDescriptor) == 0 {
			return fmt.Errorf("no certifcate known from this service provider")
		}
		if request == nil || request.KeyInfo == nil || request.KeyInfo.X509Data == nil || len(request.KeyInfo.X509Data) == 0 {
			return fmt.Errorf("no certifcate provided in request")
		}

		for _, keyDesc := range metadata.SPSSODescriptor.KeyDescriptor {
			for _, spX509Data := range keyDesc.KeyInfo.X509Data {
				for _, reqX509Data := range request.KeyInfo.X509Data {
					if spX509Data.X509Certificate == reqX509Data.X509Certificate {
						return nil
					}
				}
			}
		}

		return fmt.Errorf("unknown certificate used to sign request")
	}
}

func GetAcsUrlAndBindingForResponse(
	acs []md.IndexedEndpointType,
	requestProtocolBinding string,
	requestAcsUrl string,
	requestAcsIndex *int,
) (string, string) {
	// Step 1: If ACS URL is specified, prefer exact match by URL + Binding
	if requestAcsUrl != "" {
		for _, ac := range acs {
			if ac.Binding == requestProtocolBinding && ac.Location == requestAcsUrl {
				return ac.Location, ac.Binding
			}
		}
	}

	// Step 2: If ACS Index is specified, match it
	if requestAcsIndex != nil {
		for _, ac := range acs {
			i, err := strconv.Atoi(ac.Index)
			if err != nil {
				continue
			}
			if i == *requestAcsIndex {
				return ac.Location, ac.Binding
			}
		}
	}

	// Step 3: First match by binding
	for _, ac := range acs {
		if ac.Binding == requestProtocolBinding {
			return ac.Location, ac.Binding
		}
	}

	// Step 4: Match default ACS
	for _, ac := range acs {
		if ac.IsDefault == "true" {
			return ac.Location, ac.Binding
		}
	}

	// Step 5: Fallback to lowest index
	acsUrl := ""
	protocolBinding := ""
	minIndex := -1
	for _, ac := range acs {
		i, err := strconv.Atoi(ac.Index)
		if err != nil {
			continue
		}
		if minIndex == -1 || i < minIndex {
			minIndex = i
			acsUrl = ac.Location
			protocolBinding = ac.Binding
		}
	}
	if acsUrl != "" && protocolBinding != "" {
		return acsUrl, protocolBinding
	}

	// Step 6: Fallback to first ACS entry (if any)
	if len(acs) > 0 {
		return acs[0].Location, acs[0].Binding
	}

	// Nothing matched
	return "", ""
}
