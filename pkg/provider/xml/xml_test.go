package xml_test

import (
	"reflect"
	"testing"

	"github.com/zitadel/saml/pkg/provider/xml"
)

type XML struct {
	InnerXml string `xml:",innerxml"`
}

func Test_XmlMarshal(t *testing.T) {
	type res struct {
		metadata []byte
		err      bool
	}

	tests := []struct {
		name string
		arg  string
		res  res
	}{
		{
			name: "xml struct",
			arg:  "<test></test>",
			res: res{
				metadata: []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<XML><test></test></XML>"),
				err:      false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xmlStruct := XML{InnerXml: tt.arg}

			xmlData, err := xml.Marshal(xmlStruct)
			if (err != nil) != tt.res.err {
				t.Errorf("Marshal() error: %v", err)
				return
			}

			if !reflect.DeepEqual(tt.res.metadata, xmlData) {
				t.Errorf("Marshal() error expected: %v, got %v", tt.res.metadata, xmlData)
				return
			}
		})
	}
}
