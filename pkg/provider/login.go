package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/zitadel/logging"

	"github.com/zitadel/saml/pkg/provider/models"
	"github.com/zitadel/saml/pkg/provider/xml/samlp"
)

func (p *IdentityProvider) callbackHandleFunc(w http.ResponseWriter, r *http.Request) {
	response := &Response{
		PostTemplate: p.postTemplate,
		ErrorFunc: func(err error) {
			http.Error(w, fmt.Errorf("failed to send response: %w", err).Error(), http.StatusInternalServerError)
		},
		Issuer: p.GetEntityID(r.Context()),
	}

	if err := r.ParseForm(); err != nil {
		logging.Error(err)
		http.Error(w, fmt.Errorf("failed to parse form: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	requestID := r.Form.Get("id")
	if requestID == "" {
		err := fmt.Errorf("no requestID provided")
		logging.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authRequest, err := p.storage.AuthRequestByID(r.Context(), requestID)
	if err != nil {
		logging.Error(err)
		response.sendBackResponse(r, w, p.errorResponse(response, StatusCodeRequestDenied, fmt.Errorf("failed to get request: %w", err).Error()))
		return
	}
	response.RequestID = authRequest.GetAuthRequestID()
	response.RelayState = authRequest.GetRelayState()
	response.ProtocolBinding = authRequest.GetBindingType()
	response.AcsUrl = authRequest.GetAccessConsumerServiceURL()

	entityID, err := p.storage.GetEntityIDByAppID(r.Context(), authRequest.GetApplicationID())
	if err != nil {
		logging.Error(err)
		http.Error(w, fmt.Errorf("failed to get entityID: %w", err).Error(), http.StatusInternalServerError)
		return
	}
	response.Audience = entityID

	samlResponse, err := p.loginResponse(r.Context(), authRequest, response)
	if err != nil {
		response.sendBackResponse(r, w, response.makeFailedResponse(err, "failed to create response", p.TimeFormat))
		return
	}

	response.sendBackResponse(r, w, samlResponse)
	return
}

func (p *IdentityProvider) loginResponse(ctx context.Context, authRequest models.AuthRequestInt, response *Response) (*samlp.ResponseType, error) {
	if !authRequest.Done() {
		logging.Error(StatusCodeAuthNFailed)
		return nil, StatusCodeAuthNFailed
	}

	attrs := &Attributes{}
	if err := p.storage.SetUserinfoWithUserID(ctx, authRequest.GetApplicationID(), attrs, authRequest.GetUserID(), []int{}); err != nil {
		logging.Error(err)
		return nil, StatusCodeInvalidAttrNameOrValue
	}

	cert, key, err := getResponseCert(ctx, p.storage)
	if err != nil {
		logging.Error(err)
		return nil, StatusCodeInvalidAttrNameOrValue
	}

	samlResponse := response.makeSuccessfulResponse(attrs, p.TimeFormat, p.Expiration)
	if err := createSignature(response, samlResponse, key, cert, p.conf.SignatureAlgorithm); err != nil {
		logging.Error(err)
		return nil, StatusCodeResponder
	}
	return samlResponse, nil
}

func (p *IdentityProvider) errorResponse(response *Response, reason error, description string) *samlp.ResponseType {
	return response.makeFailedResponse(reason, description, p.TimeFormat)
}
