package provider

import (
	"fmt"
	"net/http"

	"github.com/zitadel/logging"
)

func (p *IdentityProvider) callbackHandleFunc(w http.ResponseWriter, r *http.Request) {
	response := &Response{
		PostTemplate: p.postTemplate,
		ErrorFunc: func(err error) {
			http.Error(w, fmt.Errorf("failed to send response: %w", err).Error(), http.StatusInternalServerError)
		},
		Issuer: p.GetEntityID(r.Context()),
	}

	ctx := r.Context()
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
		response.sendBackResponse(r, w, response.makeDeniedResponse(fmt.Errorf("failed to get request: %w", err).Error()))
		return
	}
	response.RequestID = authRequest.GetAuthRequestID()
	response.RelayState = authRequest.GetRelayState()
	response.ProtocolBinding = authRequest.GetBindingType()
	response.AcsUrl = authRequest.GetAccessConsumerServiceURL()

	if !authRequest.Done() {
		logging.Error(err)
		http.Error(w, fmt.Errorf("failed to get entityID: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	entityID, err := p.storage.GetEntityIDByAppID(r.Context(), authRequest.GetApplicationID())
	if err != nil {
		logging.Error(err)
		http.Error(w, fmt.Errorf("failed to get entityID: %w", err).Error(), http.StatusInternalServerError)
		return
	}
	response.Audience = entityID

	attrs := &Attributes{}
	if err := p.storage.SetUserinfoWithUserID(ctx, attrs, authRequest.GetUserID(), []int{}); err != nil {
		logging.Error(err)
		http.Error(w, fmt.Errorf("failed to get userinfo: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	samlResponse := response.makeSuccessfulResponse(attrs)

	switch response.ProtocolBinding {
	case PostBinding:
		if err := createPostSignature(r.Context(), samlResponse, p); err != nil {
			logging.Error(err)
			response.sendBackResponse(r, w, response.makeResponderFailResponse(fmt.Errorf("failed to sign response: %w", err).Error()))
			return
		}
	case RedirectBinding:
		if err := createRedirectSignature(r.Context(), samlResponse, p, response); err != nil {
			logging.Error(err)
			response.sendBackResponse(r, w, response.makeResponderFailResponse(fmt.Errorf("failed to sign response: %w", err).Error()))
			return
		}
	}

	response.sendBackResponse(r, w, samlResponse)
	return
}
