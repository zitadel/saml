package provider

import (
	"html/template"
	"io"
	"log"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestResponse_sendBackResponse(t *testing.T) {
	type args struct {
		id           string
		requestID    string
		acsURL       string
		issueInstant string
		status       string
		message      string
		issuer       string

		errorFunc       func(err error)
		protocolBinding string
		postTemplate    *template.Template
		relayState      string
		sigAlg          string
		signature       string
	}
	type res struct {
		err        bool
		statusCode int
		body       []byte
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"response post",
			args{
				id:           "id",
				requestID:    "request",
				acsURL:       "https://example",
				issueInstant: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Format(DefaultTimeFormat),
				status:       "status",
				message:      "message",
				issuer:       "issuer",

				protocolBinding: PostBinding,
				relayState:      "relayState",
				sigAlg:          "alg",
				signature:       "sig",
			},
			res{
				body: []byte("\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\"\n\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\n<body onload=\"document.getElementById('samlpost').submit()\">\n<noscript>\n<p>\n<strong>Note:</strong> Since your browser does not support JavaScript,\nyou must press the Continue button once to proceed.\n</p>\n</noscript>\n<form action=\"https://example\" method=\"post\" id=\"samlpost\">\n<div>\n<input type=\"hidden\" name=\"RelayState\"\nvalue=\"relayState\"/>\n<input type=\"hidden\" name=\"SAMLResponse\"\nvalue=\"PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPFJlc3BvbnNlIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJpZCIgSW5SZXNwb25zZVRvPSJyZXF1ZXN0IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAwMC0wMS0wMVQwMDowMDowMFoiIERlc3RpbmF0aW9uPSJodHRwczovL2V4YW1wbGUiPjxJc3N1ZXIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5pc3N1ZXI8L0lzc3Vlcj48U3RhdHVzIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxTdGF0dXNDb2RlIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIFZhbHVlPSJzdGF0dXMiPjwvU3RhdHVzQ29kZT48U3RhdHVzTWVzc2FnZT5tZXNzYWdlPC9TdGF0dXNNZXNzYWdlPjwvU3RhdHVzPjxBc3NlcnRpb24geG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIFZlcnNpb249IiIgSUQ9IiIgSXNzdWVJbnN0YW50PSIiPjxJc3N1ZXIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjwvSXNzdWVyPjwvQXNzZXJ0aW9uPjwvUmVzcG9uc2U&#43;\"/>\n</div>\n<noscript>\n<div>\n<input type=\"submit\" value=\"Continue\"/>\n</div>\n</noscript>\n</form>\n</body>\n</html>"),
			},
		},
		{
			"response redirect",
			args{
				id:           "id",
				requestID:    "request",
				acsURL:       "acs",
				issueInstant: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Format(DefaultTimeFormat),
				status:       "status",
				message:      "message",
				issuer:       "issuer",

				protocolBinding: RedirectBinding,
				relayState:      "relayState",
				sigAlg:          "alg",
				signature:       "sig",
			},
			res{
				body: []byte("<a href=\"/acs?SAMLResponse=nJJBawIxEIXv%2FRVh7utGTyUkEakIC%2FVSrYfewu5UAruJzcwW%2B%2B%2BLkSj0ULqFQMgw37zhvejleejFJybyMRiYzyQIDG3sfDgaeN1vqkdY2gf9gnSKgVCchz6QgTEFFR15UsENSIpbtVttn9ViJtUpRY5t7EE0awO%2BA9GEwu%2BjgYQfIxKDOBTZxUW2IRqxCcQusIGFlLKS80rO91KqfN5ArJHYB8eZci2B1RlLf9nLEWG6oCA2MQ2Of2%2B%2FVHxXvedWhYE9f4H1WU7XV1mrd%2Bx4pEm2FOgpdhP9PLh%2BRAOUcbC6vg8qQ7dI5I5oh%2BtdWkq5vK1eFTcmWncL7Rrvz9z%2BmYi9O1rfNrO6Lv%2FGfgcAAP%2F%2F&amp;RelayState=relayState&amp;Signature=sig&amp;SigAlg=alg\">Found</a>.\n\n"),
			},
		},
		{
			"response redirect no message",
			args{
				id:           "id",
				requestID:    "request",
				acsURL:       "acs",
				issueInstant: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Format(DefaultTimeFormat),
				status:       "status",
				message:      "",
				issuer:       "issuer",

				protocolBinding: RedirectBinding,
				relayState:      "relayState",
				sigAlg:          "alg",
				signature:       "sig",
			},
			res{
				body: []byte("<a href=\"/acs?SAMLResponse=nJLBSgMxEIbvPkWY%2B3bTniQkKcVSWNCLrT14C7ujBHYnNTMr9e2lKduCB7FCLgnz5Z98E7s8Dr36xMwxkYP5TINCalMX6d3By25T3cPS39ln5EMiRnUcemIHYyaTAkc2FAZkI63Zrp4ezWKmzSEnSW3qQTVrB7ED1dDE75KDjB8jsoDaT7GLU2zDPGJDLIHEwUJrXel5pec7rU1Zr6DWyBIpSKFCy%2BBtwfJf%2BgrMmE8oqE3KQ5Dfy08nsaveSqlBkihf4GOJs%2FU51tutBBn5Ji0T9JC6G33uQz%2BiAy44eFtfL7psvF1N77xRymUc58H9nMg%2FXfurq%2FrSmbf19CP8dwAAAP%2F%2F&amp;RelayState=relayState&amp;Signature=sig&amp;SigAlg=alg\">Found</a>.\n\n"),
			},
		},
		{
			"response redirect no acs",
			args{
				id:           "id",
				requestID:    "request",
				acsURL:       "",
				issueInstant: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Format(DefaultTimeFormat),
				status:       "status",
				message:      "",
				issuer:       "issuer",

				protocolBinding: RedirectBinding,
				relayState:      "relayState",
				sigAlg:          "alg",
				signature:       "sig",
			},
			res{
				body: []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Response xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"id\" InResponseTo=\"request\" Version=\"2.0\" IssueInstant=\"2000-01-01T00:00:00Z\"><Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">issuer</Issuer><Status xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\"><StatusCode xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" Value=\"status\"></StatusCode></Status><Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"\" ID=\"\" IssueInstant=\"\"><Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"></Issuer></Assertion></Response>"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			w := httptest.NewRecorder()

			r := makeResponse(tt.args.id, tt.args.requestID, tt.args.acsURL, tt.args.issueInstant, tt.args.status, tt.args.message, tt.args.issuer)

			var errF error
			temp, _ := template.New("post").Parse(postTemplate)
			response := &Response{
				ProtocolBinding: tt.args.protocolBinding,
				RelayState:      tt.args.relayState,
				AcsUrl:          tt.args.acsURL,
				SigAlg:          tt.args.sigAlg,
				Signature:       tt.args.signature,
				ErrorFunc: func(err error) {
					errF = err
				},
				PostTemplate: temp,
			}

			response.sendBackResponse(req, w, r)
			if (errF != nil) != tt.res.err {
				t.Errorf("sendBackResponse() got = %v, want %v", errF, tt.res.err)
				return
			}
			got := w.Result()
			defer got.Body.Close()

			b, err := io.ReadAll(got.Body)
			if err != nil {
				log.Fatalln(err)
			}
			if !reflect.DeepEqual(b, tt.res.body) {
				t.Errorf("sendBackResponse() got = %v, want %v", b, tt.res.body)
			}
		})
	}
}
