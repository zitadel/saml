package provider

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/zitadel/saml/pkg/provider/xml"
	"github.com/zitadel/saml/pkg/provider/xml/saml"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

const (
	StatusCodeSuccess                = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusCodeVersionMissmatch       = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
	StatusCodeAuthNFailed            = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	StatusCodeInvalidAttrNameOrValue = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
	StatusCodeInvalidNameIDPolicy    = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
	StatusCodeRequestDenied          = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	StatusCodeRequestUnsupported     = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
	StatusCodeUnsupportedBinding     = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
	StatusCodeResponder              = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	StatusCodePartialLogout          = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
)

type Response struct {
	PostTemplate    *template.Template
	ProtocolBinding string
	RelayState      string
	AcsUrl          string
	Signature       string
	SigAlg          string
	ErrorFunc       func(err error)

	RequestID string
	Issuer    string
	Audience  string
	SendIP    string
}

type authResponseForm struct {
	RelayState                  string
	SAMLResponse                string
	AssertionConsumerServiceURL string
}

func (r *Response) sendBackResponse(
	req *http.Request,
	w http.ResponseWriter,
	resp *samlp.ResponseType,
) {
	respData, err := xml.Marshal(resp)
	if err != nil {
		r.ErrorFunc(err)
		return
	}

	if r.AcsUrl == "" {
		if err := xml.Write(w, respData); err != nil {
			r.ErrorFunc(err)
			return
		}
		return
	}

	switch r.ProtocolBinding {
	case PostBinding:
		respData := base64.StdEncoding.EncodeToString(respData)

		data := authResponseForm{
			r.RelayState,
			respData,
			r.AcsUrl,
		}

		if err := r.PostTemplate.Execute(w, data); err != nil {
			r.ErrorFunc(err)
			return
		}
	case RedirectBinding:
		respData, err := xml.DeflateAndBase64(respData)
		if err != nil {
			r.ErrorFunc(err)
			return
		}

		http.Redirect(w, req, fmt.Sprintf("%s?%s", r.AcsUrl, BuildRedirectQuery(string(respData), r.RelayState, r.SigAlg, r.Signature)), http.StatusFound)
		return
	default:
		//TODO: no binding
	}
}

func createSignature(response *Response, samlResponse *samlp.ResponseType, key *rsa.PrivateKey, cert []byte, signatureAlgorithm string) error {
	switch response.ProtocolBinding {
	case PostBinding:
		if err := createPostSignature(samlResponse, key, cert, signatureAlgorithm); err != nil {
			return fmt.Errorf("failed to sign response: %w", err)
		}
	case RedirectBinding:
		sig, sigAlg, err := createRedirectSignature(samlResponse, key, cert, signatureAlgorithm, response.RelayState)
		if err != nil {
			return fmt.Errorf("failed to sign response: %w", err)
		}
		response.Signature = sig
		response.SigAlg = sigAlg
	}
	return nil
}

func (r *Response) makeFailedResponse(
	reason string,
	message string,
	timeFormat string,
) *samlp.ResponseType {
	now := time.Now().UTC()
	nowStr := now.Format(timeFormat)
	return makeResponse(
		NewID(),
		r.RequestID,
		r.AcsUrl,
		nowStr,
		reason,
		message,
		r.Issuer,
	)
}

func (r *Response) makeSuccessfulResponse(
	attributes *Attributes,
	timeFormat string,
	expiration time.Duration,
) *samlp.ResponseType {
	now := time.Now().UTC()
	nowStr := now.Format(timeFormat)
	fiveFromNowStr := now.Add(expiration).Format(timeFormat)

	return r.makeAssertionResponse(
		nowStr,
		fiveFromNowStr,
		attributes,
	)
}

func (r *Response) makeAssertionResponse(
	issueInstant string,
	untilInstant string,
	attributes *Attributes,
) *samlp.ResponseType {

	response := makeResponse(NewID(), r.RequestID, r.AcsUrl, issueInstant, StatusCodeSuccess, "", r.Issuer)
	assertion := makeAssertion(r.RequestID, r.AcsUrl, r.SendIP, issueInstant, untilInstant, r.Issuer, attributes.GetNameID(), attributes.GetSAML(), r.Audience, true)
	response.Assertion = *assertion
	return response
}

func getIssuer(entityID string) *saml.NameIDType {
	return &saml.NameIDType{
		Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
		Text:   entityID,
	}
}

func makeAttributeQueryResponse(
	requestID string,
	issuer string,
	entityID string,
	attributes *Attributes,
	queriedAttrs []saml.AttributeType,
	timeFormat string,
) *samlp.ResponseType {
	now := time.Now().UTC()
	nowStr := now.Format(timeFormat)
	fiveMinutes, _ := time.ParseDuration("5m")
	fiveFromNow := now.Add(fiveMinutes)
	fiveFromNowStr := fiveFromNow.Format(timeFormat)

	providedAttrs := []*saml.AttributeType{}
	attrsSaml := attributes.GetSAML()
	if queriedAttrs == nil || len(queriedAttrs) == 0 {
		for _, attrSaml := range attrsSaml {
			providedAttrs = append(providedAttrs, attrSaml)
		}
	} else {
		for _, attrSaml := range attrsSaml {
			for _, queriedAttr := range queriedAttrs {
				if attrSaml.Name == queriedAttr.Name && attrSaml.NameFormat == queriedAttr.NameFormat {
					providedAttrs = append(providedAttrs, attrSaml)
				}
			}
		}
	}

	response := makeResponse(NewID(), requestID, "", nowStr, StatusCodeSuccess, "", issuer)
	assertion := makeAssertion(requestID, "", "", nowStr, fiveFromNowStr, issuer, attributes.GetNameID(), providedAttrs, entityID, false)
	response.Assertion = *assertion
	return response
}

func makeAssertion(
	requestID string,
	acsURL string,
	sendIP string,
	issueInstant string,
	untilInstant string,
	issuer string,
	nameID *saml.NameIDType,
	attributes []*saml.AttributeType,
	audience string,
	authN bool,
) *saml.AssertionType {
	id := NewID()
	issuerP := getIssuer(issuer)

	ret := &saml.AssertionType{
		Version:      "2.0",
		Id:           id,
		IssueInstant: issueInstant,
		Issuer:       *issuerP,
		Subject: &saml.SubjectType{
			NameID: nameID,
			SubjectConfirmation: []saml.SubjectConfirmationType{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationDataType{
						InResponseTo: requestID,
						NotOnOrAfter: untilInstant,
					},
				},
			},
		},
		Conditions: &saml.ConditionsType{
			NotBefore:    issueInstant,
			NotOnOrAfter: untilInstant,
			AudienceRestriction: []saml.AudienceRestrictionType{
				{Audience: []string{audience}},
			},
		},
		AttributeStatement: []saml.AttributeStatementType{
			{Attribute: attributes},
		},
	}
	if acsURL != "" {
		ret.Subject.SubjectConfirmation[0].SubjectConfirmationData.Recipient = acsURL
	}
	if sendIP != "" {
		ret.Subject.SubjectConfirmation[0].SubjectConfirmationData.Address = sendIP
	}
	if authN {
		ret.AuthnStatement = []saml.AuthnStatementType{
			{
				AuthnInstant: issueInstant,
				SessionIndex: id,
				AuthnContext: saml.AuthnContextType{
					AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
		}
	}
	return ret
}

func makeResponse(
	id string,
	requestID string,
	acsURL string,
	issueInstant string,
	status string,
	message string,
	issuer string,
) *samlp.ResponseType {
	resp := &samlp.ResponseType{
		Version:      "2.0",
		Id:           id,
		IssueInstant: issueInstant,
		Status: samlp.StatusType{
			StatusCode: samlp.StatusCodeType{
				Value: status,
			},
			StatusMessage: message,
		},
		InResponseTo: requestID,
		Issuer:       getIssuer(issuer),
	}

	if acsURL != "" {
		resp.Destination = acsURL
	}
	return resp
}
