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
			http.Error(w, fmt.Errorf("failed to parse form: %w", err).Error(), http.StatusInternalServerError)
		},
	)

	// verify that request is not empty
	checkerInstance.WithValueNotEmptyCheck(
		"SAMLRequest",
		func() string { return authRequestForm.AuthRequest },
		func() {
			response.sendBackResponse(r, w, response.makeDeniedResponse(fmt.Errorf("no auth request provided").Error(), p.timeFormat))
		},
	)

	// verify that there is a signature provided if signature algorithm is provided
	checkerInstance.WithConditionalValueNotEmpty(
		func() bool { return authRequestForm.SigAlg != "" },
		"Signature",
		func() string { return authRequestForm.Sig },
		func() {
			response.sendBackResponse(r, w, response.makeDeniedResponse(fmt.Errorf("signature algorith provided but no signature").Error(), p.timeFormat))
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
			response.sendBackResponse(r, w, response.makeDeniedResponse(fmt.Errorf("failed to decode request").Error(), p.timeFormat))
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
			response.sendBackResponse(r, w, response.makeDeniedResponse(fmt.Errorf("failed to find registered serviceprovider: %w", err).Error(), p.timeFormat))
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
			response.sendBackResponse(r, w, response.makeDeniedResponse(fmt.Errorf("failed to validate certificate from request: %w", err).Error(), p.timeFormat))
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
			response.sendBackResponse(r, w, response.makeDeniedResponse(fmt.Errorf("failed to verify signature: %w", err).Error(), p.timeFormat))
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
			response.sendBackResponse(r, w, response.makeDeniedResponse(fmt.Errorf("failed to verify signature: %w", err).Error(), p.timeFormat))
		},
	)

	// work out used acs url and protocolbinding for response
	checkerInstance.WithValueStep(
		func() {
			response.AcsUrl, response.ProtocolBinding = getAcsUrlAndBindingForResponse(sp, authNRequest.ProtocolBinding)
		},
	)

	// check if supported acs url is provided
	checkerInstance.WithValueNotEmptyCheck(
		"acsUrl",
		func() string { return response.AcsUrl },
		func() {
			response.sendBackResponse(r, w, response.makeUnsupportedBindingResponse(fmt.Errorf("missing usable assertion consumer url").Error(), p.timeFormat))
		},
	)

	// check if supported protocolbinding is provided
	checkerInstance.WithValueNotEmptyCheck(
		"protocol binding",
		func() string { return response.ProtocolBinding },
		func() {
			response.sendBackResponse(r, w, response.makeUnsupportedBindingResponse(fmt.Errorf("missing usable protocol binding").Error(), p.timeFormat))
		},
	)

	checkerInstance.WithLogicStep(
		checkRequestRequiredContent(
			func() *md.IDPSSODescriptorType { return metadata },
			func() *serviceprovider.ServiceProvider { return sp },
			func() *samlp.AuthnRequestType { return authNRequest },
		),
		func() {
			response.sendBackResponse(r, w, response.makeDeniedResponse(fmt.Errorf("failed to validate request content: %w", err).Error(), p.timeFormat))
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
			response.sendBackResponse(r, w, response.makeResponderFailResponse(fmt.Errorf("failed to persist request: %w", err).Error(), p.timeFormat))
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
		response.sendBackResponse(r, w, response.makeUnsupportedBindingResponse(fmt.Errorf("unsupported binding: %s", response.ProtocolBinding).Error(), p.timeFormat))
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

func getAcsUrlAndBindingForResponse(
	sp *serviceprovider.ServiceProvider,
	requestProtocolBinding string,
) (string, string) {
	acsUrl := ""
	protocolBinding := ""

	for _, acs := range sp.Metadata.SPSSODescriptor.AssertionConsumerService {
		if acs.Binding == requestProtocolBinding {
			acsUrl = acs.Location
			protocolBinding = acs.Binding
			break
		}
	}
	if acsUrl == "" {
		isDefaultFound := false
		for _, acs := range sp.Metadata.SPSSODescriptor.AssertionConsumerService {
			if acs.IsDefault == "true" {
				isDefaultFound = true
				acsUrl = acs.Location
				protocolBinding = acs.Binding
				break
			}
		}
		if !isDefaultFound {
			index := 0
			for _, acs := range sp.Metadata.SPSSODescriptor.AssertionConsumerService {
				i, _ := strconv.Atoi(acs.Index)
				if index == 0 || i < index {
					acsUrl = acs.Location
					protocolBinding = acs.Binding
					index = i
				}
			}
		}
	}

	return acsUrl, protocolBinding
}
