package provider

import (
	"encoding/base64"
	"html/template"
	"net/http"
	"time"

	"github.com/zitadel/saml/pkg/provider/xml"
	"github.com/zitadel/saml/pkg/provider/xml/saml"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

type LogoutResponse struct {
	LogoutTemplate *template.Template
	RelayState     string
	SAMLResponse   string
	LogoutURL      string

	RequestID string
	Issuer    string
	ErrorFunc func(err error)
}

type LogoutResponseForm struct {
	RelayState   string
	SAMLResponse string
	LogoutURL    string
}

func (r *LogoutResponse) sendBackLogoutResponse(w http.ResponseWriter, resp *samlp.LogoutResponseType) {
	respData, err := xml.Marshal(resp)
	if err != nil {
		r.ErrorFunc(err)
		return
	}

	if r.LogoutURL == "" {
		if err := xml.Write(w, respData); err != nil {
			r.ErrorFunc(err)
			return
		}
		return
	}

	data := LogoutResponseForm{
		RelayState:   r.RelayState,
		SAMLResponse: base64.StdEncoding.EncodeToString(respData),
		LogoutURL:    r.LogoutURL,
	}

	if err := r.LogoutTemplate.Execute(w, data); err != nil {
		r.ErrorFunc(err)
		return
	}
}

func (r *LogoutResponse) makeFailedLogoutResponse(
	reason error,
	message string,
	timeFormat string,
) *samlp.LogoutResponseType {
	return makeLogoutResponse(
		r.RequestID,
		r.LogoutURL,
		time.Now().UTC().Format(timeFormat),
		reason.Error(),
		message,
		getIssuer(r.Issuer),
	)
}

func (r *LogoutResponse) makeSuccessfulLogoutResponse(timeFormat string) *samlp.LogoutResponseType {
	return makeLogoutResponse(
		r.RequestID,
		r.LogoutURL,
		time.Now().UTC().Format(timeFormat),
		statusCodeSuccess.Error(),
		"",
		getIssuer(r.Issuer),
	)
}

func makeLogoutResponse(
	requestID string,
	logoutURL string,
	issueInstant string,
	status string,
	message string,
	issuer *saml.NameIDType,
) *samlp.LogoutResponseType {
	return &samlp.LogoutResponseType{
		Id:           NewID(),
		InResponseTo: requestID,
		Version:      "2.0",
		IssueInstant: issueInstant,
		Destination:  logoutURL,
		Issuer:       issuer,
		Status: samlp.StatusType{
			StatusCode: samlp.StatusCodeType{
				Value: status,
			},
			StatusMessage: message,
		},
	}
}
