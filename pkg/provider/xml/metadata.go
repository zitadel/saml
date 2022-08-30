package xml

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	"github.com/zitadel/saml/pkg/provider/xml/md"
)

func ReadMetadataFromURL(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error while reading metadata with statusCode: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func ParseMetadataXmlIntoStruct(xmlData []byte) (*md.EntityDescriptorType, error) {
	metadata := &md.EntityDescriptorType{}
	if err := xml.Unmarshal(xmlData, metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

func GetCertsFromKeyDescriptors(keyDescs []md.KeyDescriptorType) []string {
	certStrs := []string{}
	if keyDescs == nil {
		return certStrs
	}
	for _, keyDescriptor := range keyDescs {
		for _, x509Data := range keyDescriptor.KeyInfo.X509Data {
			if len(x509Data.X509Certificate) != 0 {
				switch keyDescriptor.Use {
				case "", "signing":
					certStrs = append(certStrs, x509Data.X509Certificate)
				}
			}
		}
	}
	return certStrs
}
