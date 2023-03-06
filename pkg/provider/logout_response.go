package provider

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"html/template"
	"net/http"
	"time"

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
	var xmlbuff bytes.Buffer

	memWriter := bufio.NewWriter(&xmlbuff)
	_, err := memWriter.Write([]byte(xml.Header))
	if err != nil {
		r.ErrorFunc(err)
		return
	}

	encoder := xml.NewEncoder(memWriter)
	err = encoder.Encode(resp)
	if err != nil {
		r.ErrorFunc(err)
		return
	}

	err = memWriter.Flush()
	if err != nil {
		r.ErrorFunc(err)
		return
	}

	samlMessage := base64.StdEncoding.EncodeToString(xmlbuff.Bytes())

	data := LogoutResponseForm{
		RelayState:   r.RelayState,
		SAMLResponse: samlMessage,
		LogoutURL:    r.LogoutURL,
	}

	if err := r.LogoutTemplate.Execute(w, data); err != nil {
		r.ErrorFunc(err)
		return
	}
}

func (r *LogoutResponse) makeSuccessfulLogoutResponse(timeFormat string) *samlp.LogoutResponseType {
	return makeLogoutResponse(
		r.RequestID,
		r.LogoutURL,
		time.Now().UTC().Format(timeFormat),
		StatusCodeSuccess,
		"",
		getIssuer(r.Issuer),
	)
}

func (r *LogoutResponse) makeUnsupportedlLogoutResponse(
	message string,
	timeFormat string,
) *samlp.LogoutResponseType {
	return makeLogoutResponse(
		r.RequestID,
		r.LogoutURL,
		time.Now().UTC().Format(timeFormat),
		StatusCodeRequestUnsupported,
		message,
		getIssuer(r.Issuer),
	)
}

func (r *LogoutResponse) makePartialLogoutResponse(
	message string,
	timeFormat string,
) *samlp.LogoutResponseType {
	return makeLogoutResponse(
		r.RequestID,
		r.LogoutURL,
		time.Now().UTC().Format(timeFormat),
		StatusCodePartialLogout,
		message,
		getIssuer(r.Issuer),
	)
}

func (r *LogoutResponse) makeDeniedLogoutResponse(
	message string,
	timeFormat string,
) *samlp.LogoutResponseType {
	return makeLogoutResponse(
		r.RequestID,
		r.LogoutURL,
		time.Now().UTC().Format(timeFormat),
		StatusCodeRequestDenied,
		message,
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
