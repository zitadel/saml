package provider

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/pkg/op"
	"github.com/zitadel/saml/pkg/provider/signature"
	saml_xml "github.com/zitadel/saml/pkg/provider/xml"
	"github.com/zitadel/saml/pkg/provider/xml/md"
	"github.com/zitadel/saml/pkg/provider/xml/xenc"
	"github.com/zitadel/saml/pkg/provider/xml/xml_dsig"
	"net/http"
)

func (p *Provider) metadataHandle(w http.ResponseWriter, r *http.Request) {
	metadata, err := p.GetMetadata()
	if err != nil {
		err := fmt.Errorf("error while getting metadata: %w", err)
		logging.Log("SAML-mp2ok3").Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := saml_xml.WriteXMLMarshalled(w, metadata); err != nil {
		http.Error(w, fmt.Errorf("failed to respond with metadata").Error(), http.StatusInternalServerError)
		return
	}
}

func (p *IdentityProviderConfig) getMetadata(
	metadataEndpoint *op.Endpoint,
	idpCertData []byte,
) (*md.IDPSSODescriptorType, *md.AttributeAuthorityDescriptorType) {
	idpKeyDescriptors := []md.KeyDescriptorType{
		{
			Use: md.KeyTypesSigning,
			KeyInfo: xml_dsig.KeyInfoType{
				KeyName: []string{metadataEndpoint.Absolute("") + " IDP " + string(md.KeyTypesSigning)},
				X509Data: []xml_dsig.X509DataType{{
					X509Certificate: base64.StdEncoding.EncodeToString(idpCertData),
				}},
			},
		},
	}

	if p.EncryptionAlgorithm != "" {
		idpKeyDescriptors = append(idpKeyDescriptors, md.KeyDescriptorType{
			Use: md.KeyTypesEncryption,
			KeyInfo: xml_dsig.KeyInfoType{
				KeyName: []string{metadataEndpoint.Absolute("") + " IDP " + string(md.KeyTypesEncryption)},
				X509Data: []xml_dsig.X509DataType{{
					X509Certificate: base64.StdEncoding.EncodeToString(idpCertData),
				}},
			},
			EncryptionMethod: []xenc.EncryptionMethodType{{
				Algorithm: p.EncryptionAlgorithm,
			}},
		})
	}

	attrs := &Attributes{
		"empty", "empty", "empty", "empty", "empty", "empty",
	}
	attrsSaml := attrs.GetSAML()
	for _, attr := range attrsSaml {
		for i := range attr.AttributeValue {
			attr.AttributeValue[i] = ""
		}
	}

	return &md.IDPSSODescriptorType{
			XMLName:                    xml.Name{},
			WantAuthnRequestsSigned:    p.WantAuthRequestsSigned,
			Id:                         NewID(),
			ValidUntil:                 p.MetadataIDPConfig.ValidUntil,
			CacheDuration:              p.MetadataIDPConfig.CacheDuration,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			ErrorURL:                   p.MetadataIDPConfig.ErrorURL,
			SingleSignOnService: []md.EndpointType{
				{
					Binding:  RedirectBinding,
					Location: p.Endpoints.SingleSignOn.URL,
				}, {
					Binding:  PostBinding,
					Location: p.Endpoints.SingleSignOn.URL,
				},
			},
			//TODO definition for more profiles
			AttributeProfile: []string{
				"urn:oasis:names:tc:SAML:2.0:profiles:attribute:basic",
			},
			Attribute: attrsSaml,
			ArtifactResolutionService: []md.IndexedEndpointType{{
				Index:     "0",
				IsDefault: "true",
				Binding:   SOAPBinding,
				Location:  p.Endpoints.Artifact.URL,
			}},
			SingleLogoutService: []md.EndpointType{
				{
					Binding:  SOAPBinding,
					Location: p.Endpoints.SLOArtifact.URL,
				},
				{
					Binding:  RedirectBinding,
					Location: p.Endpoints.SingleLogOut.URL,
				},
				{
					Binding:  PostBinding,
					Location: p.Endpoints.SingleLogOut.URL,
				},
			},
			NameIDFormat:  []string{"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"},
			Signature:     nil,
			KeyDescriptor: idpKeyDescriptors,

			Organization:  nil,
			ContactPerson: nil,
			/*
				NameIDMappingService: nil,
				AssertionIDRequestService: nil,
				ManageNameIDService: nil,
			*/
		},
		&md.AttributeAuthorityDescriptorType{
			XMLName:                    xml.Name{},
			Id:                         NewID(),
			ValidUntil:                 p.MetadataIDPConfig.ValidUntil,
			CacheDuration:              p.MetadataIDPConfig.CacheDuration,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			ErrorURL:                   p.MetadataIDPConfig.ErrorURL,
			AttributeService: []md.EndpointType{{
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
				Location: p.Endpoints.Attribute.URL,
			}},
			NameIDFormat: []string{"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"},
			//TODO definition for more profiles
			AttributeProfile: []string{
				"urn:oasis:names:tc:SAML:2.0:profiles:attribute:basic",
			},
			Attribute:     attrsSaml,
			Signature:     nil,
			KeyDescriptor: idpKeyDescriptors,

			Organization:  nil,
			ContactPerson: nil,

			/*
				AssertionIDRequestService: nil,
			*/
		}
}

func (c *Config) getMetadata(
	idp *IdentityProvider,
) *md.EntityDescriptorType {

	entity := &md.EntityDescriptorType{
		XMLName:       xml.Name{Local: "md"},
		EntityID:      md.EntityIDType(idp.EntityID),
		Id:            NewID(),
		Signature:     nil,
		Organization:  nil,
		ContactPerson: nil,
		/*
			AuthnAuthorityDescriptor:     nil,
			PDPDescriptor:         nil,
			AffiliationDescriptor: nil,
		*/
	}

	if c.IDPConfig != nil {
		entity.IDPSSODescriptor = idp.Metadata
		entity.AttributeAuthorityDescriptor = idp.AAMetadata
	}

	if c.Organisation != nil {
		org := &md.OrganizationType{
			XMLName:    xml.Name{},
			Extensions: nil,
			OrganizationName: []md.LocalizedNameType{
				{Text: c.Organisation.Name},
			},
			OrganizationDisplayName: []md.LocalizedNameType{
				{Text: c.Organisation.DisplayName},
			},
			OrganizationURL: []md.LocalizedURIType{
				{Text: c.Organisation.URL},
			},
		}
		entity.AttributeAuthorityDescriptor.Organization = org
		entity.IDPSSODescriptor.Organization = org
	}

	if c.ContactPerson != nil {
		contactPerson := []md.ContactType{
			{
				XMLName:         xml.Name{},
				ContactType:     c.ContactPerson.ContactType,
				Company:         c.ContactPerson.Company,
				GivenName:       c.ContactPerson.GivenName,
				SurName:         c.ContactPerson.SurName,
				EmailAddress:    []string{c.ContactPerson.EmailAddress},
				TelephoneNumber: []string{c.ContactPerson.TelephoneNumber},
			},
		}
		entity.AttributeAuthorityDescriptor.ContactPerson = contactPerson
		entity.IDPSSODescriptor.ContactPerson = contactPerson
	}

	return entity
}

func (p *Provider) GetMetadata() (*md.EntityDescriptorType, error) {
	metadata := *p.Metadata
	idpSig, err := signature.Create(p.signer, metadata)
	if err != nil {
		return nil, err
	}
	metadata.Signature = idpSig
	return &metadata, nil
}
