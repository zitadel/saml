package xml

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/zitadel/saml/pkg/provider/xml/samlp"
	"github.com/zitadel/saml/pkg/provider/xml/soap"
	"github.com/zitadel/saml/pkg/provider/xml/xml_dsig"
)

const (
	EncodingDeflate = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"
)

func Marshal(data interface{}) ([]byte, error) {
	var xmlbuff bytes.Buffer

	memWriter := bufio.NewWriter(&xmlbuff)
	_, err := memWriter.Write([]byte(xml.Header))
	if err != nil {
		return nil, err
	}

	encoder := xml.NewEncoder(memWriter)
	err = encoder.Encode(data)
	if err != nil {
		return nil, err
	}

	err = memWriter.Flush()
	if err != nil {
		return nil, err
	}

	return xmlbuff.Bytes(), nil
}

func DeflateAndBase64(data []byte) ([]byte, error) {
	buff := &bytes.Buffer{}
	b64Encoder := base64.NewEncoder(base64.StdEncoding, buff)
	// compression level is set at 9 as BestCompression, also used by other SAML application like crewjam/saml
	flateWriter, _ := flate.NewWriter(b64Encoder, 9)
	if _, err := flateWriter.Write(data); err != nil {
		return nil, err
	}
	if err := flateWriter.Close(); err != nil {
		return nil, err
	}
	if err := b64Encoder.Close(); err != nil {
		return nil, err
	}
	return buff.Bytes(), nil
}

func WriteXMLMarshalled(w http.ResponseWriter, body interface{}) error {
	_, err := w.Write([]byte(xml.Header))
	if err != nil {
		return err
	}

	encoder := xml.NewEncoder(w)

	err = encoder.Encode(body)
	if err != nil {
		return err
	}
	err = encoder.Flush()
	return err
}

func Write(w http.ResponseWriter, body []byte) error {
	_, err := w.Write(body)
	return err
}

func DecodeAuthNRequest(encoding string, message string) (*samlp.AuthnRequestType, error) {
	data, err := InflateAndDecode(encoding, true, message)
	if err != nil {
		return nil, err
	}
	req := &samlp.AuthnRequestType{}
	if err := xml.Unmarshal(data, req); err != nil {
		return nil, err
	}
	return req, nil
}

func DecodeSignature(encoding string, b64 bool, message string) (*xml_dsig.SignatureType, error) {
	data, err := InflateAndDecode(encoding, b64, message)
	if err != nil {
		return nil, err
	}
	ret := &xml_dsig.SignatureType{}
	if err := xml.Unmarshal(data, ret); err != nil {
		return nil, err
	}
	return ret, nil
}

func DecodeAttributeQuery(request string) (*samlp.AttributeQueryType, error) {
	decoder := xml.NewDecoder(strings.NewReader(request))
	var attrEnv soap.AttributeQueryEnvelope
	err := decoder.Decode(&attrEnv)
	if err != nil {
		return nil, err
	}

	return attrEnv.Body.AttributeQuery, nil
}

func DecodeLogoutRequest(encoding string, message string) (*samlp.LogoutRequestType, error) {
	data, err := InflateAndDecode(encoding, true, message)
	if err != nil {
		return nil, err
	}
	req := &samlp.LogoutRequestType{}
	if err := xml.Unmarshal(data, req); err != nil {
		return nil, err
	}
	return req, nil
}

func DecodeResponse(encoding string, b64 bool, message string) (*samlp.ResponseType, error) {
	data, err := InflateAndDecode(encoding, b64, message)
	if err != nil {
		return nil, err
	}
	req := &samlp.ResponseType{}
	if err := xml.Unmarshal(data, req); err != nil {
		return nil, err
	}
	return req, nil
}

func InflateAndDecode(encoding string, b64 bool, message string) (_ []byte, err error) {
	data := []byte(message)
	if b64 {
		data, err = base64.StdEncoding.DecodeString(message)
		if err != nil {
			return nil, err
		}
	}
	switch encoding {
	case "":
		return data, nil
	case EncodingDeflate:
		r := flate.NewReader(bytes.NewBuffer(data))
		defer r.Close()
		return io.ReadAll(r)
	default:
		return nil, fmt.Errorf("unknown encoding")
	}
}
