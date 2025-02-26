package provider

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zitadel/saml/pkg/provider/key"
	"github.com/zitadel/saml/pkg/provider/mock"

	"github.com/golang/mock/gomock"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestIDP_certificateHandleFunc(t *testing.T) {
	type args struct {
		metadataEndpoint string
		config           *IdentityProviderConfig
		certificate      []byte
		key              []byte
		issuer           string
	}
	type res struct {
		code int
		err  bool
	}

	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"certificate 1",
			args{
				metadataEndpoint: "/saml/metadata",
				issuer:           "http://localhost:50002",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints:          &EndpointConfig{},
				},
				certificate: []byte("-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n"),
				key:         []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq\nVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc\nWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2\ngIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a\nEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7\nLfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v\n4cxTNPn/AgMBAAECggEAF+rV9yH30Ysza8GwrXCR9qDN1Dp3QmmsavnXkonEvPoq\nEr2T3o0//6mBp6CLDboMQGQBjblJwl+3Y6PgZolvHAMOsMdHfYNPEo7FSzUBzEw+\nqRrs5HkMyvoPgfV6X8F97W3tiD4Q/AmHkMILl+MxbnfPXM54gWqPuwIqxY1uaCk5\nREwyb7WBon3rd58ceOI1SLRjod6SbqWBMMSN3cJ+5VEPObFjw/RlhNQ5rBI8G5Kt\nso2zBU5C4BB2CvqlWy98WDKJkTvWHbiTjZCy8BQ+gQ6UJM2vaNELFOVpuMGQnMIi\noWiX10Jg2e1gP9j3TdrohlGF8M3+TXjSFKNmeX0DUQKBgQDx7UazUWS5RtkgnjH9\nw2xH2xkstJVD7nAS8VTxNwcrgjVXPvTJha9El904obUjyRX7ppb02tuH5ML/bZh6\n9lL4bP5+SHcJ10e4q8CK/KAGHD6BYAbaGXRq0CoSk5a3vv5XPdob4T5qKCIHFpnu\nMfbvdbEoameLOyRYOGu/yVZIiwKBgQDGQs7FRTisHV0xooiRmlvYF0dcd19qpLed\nqhgJNqBPOTEvvGvJNRoi39haEY3cuTqsxZ5FAlFlVFMUUozz+d0xBLLInoVY/Y4h\nhSdGmdw/A6oHodLqyEp3N5RZNdLlh8/nDS3xXzMotAl75bW5kc2ttcRhRdtyNJ9Z\nup0PgppO3QKBgEC45upAQz8iCiKkz+EA8C4FGqYQJcLHvmoC8GOcAioMqrKNoDVt\ns2cZbdChynEpcd0iQ058YrDnbZeiPWHgFnBp0Gf+gQI7+u8X2+oTDci0s7Au/YZJ\nuxB8YlUX8QF1clvqqzg8OVNzKy9UR5gm+9YyWVPjq5HfH6kOZx0nAxNjAoGAERt8\nqgsCC9/wxbKnpCC0oh3IG5N1WUdjTKh7sHfVN2DQ/LR+fHsniTDVg1gWbKBTDsty\nj7PWgC7ZiFxjKz45NtyX7LW4/efLFttdezsVhR500nnFMFseCdFy7Iu3afThHKfH\nehdj27RFSTqWBrAtFjsj+dzERcOCqIRwvwDe/cUCgYEA5+1mzVXDVjKsWylKJPk+\nZZA4LUfvmTj3VLNDZrlSAI/xEikCFio0QWEA2TQYTAwbXTrKwQSeHQRhv7OTc1h+\nMhpAgvs189ze5J4jiNmULEkkrO+Cxxnw8tyV+UFRZtzW9gUoVBwXiZ/Wbl9sfnlO\nwLJHc0j6OltPcPJmxHP8gQI=\n-----END PRIVATE KEY-----\n"),
			},
			res{
				code: 200,
				err:  false,
			},
		},
		{
			"certificate invalid signature algorithm",
			args{
				metadataEndpoint: "/saml/metadata",
				issuer:           "http://localhost:50002",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: "test",
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints:          &EndpointConfig{},
				},
				certificate: []byte("-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n"),
				key:         []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq\nVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc\nWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2\ngIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a\nEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7\nLfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v\n4cxTNPn/AgMBAAECggEAF+rV9yH30Ysza8GwrXCR9qDN1Dp3QmmsavnXkonEvPoq\nEr2T3o0//6mBp6CLDboMQGQBjblJwl+3Y6PgZolvHAMOsMdHfYNPEo7FSzUBzEw+\nqRrs5HkMyvoPgfV6X8F97W3tiD4Q/AmHkMILl+MxbnfPXM54gWqPuwIqxY1uaCk5\nREwyb7WBon3rd58ceOI1SLRjod6SbqWBMMSN3cJ+5VEPObFjw/RlhNQ5rBI8G5Kt\nso2zBU5C4BB2CvqlWy98WDKJkTvWHbiTjZCy8BQ+gQ6UJM2vaNELFOVpuMGQnMIi\noWiX10Jg2e1gP9j3TdrohlGF8M3+TXjSFKNmeX0DUQKBgQDx7UazUWS5RtkgnjH9\nw2xH2xkstJVD7nAS8VTxNwcrgjVXPvTJha9El904obUjyRX7ppb02tuH5ML/bZh6\n9lL4bP5+SHcJ10e4q8CK/KAGHD6BYAbaGXRq0CoSk5a3vv5XPdob4T5qKCIHFpnu\nMfbvdbEoameLOyRYOGu/yVZIiwKBgQDGQs7FRTisHV0xooiRmlvYF0dcd19qpLed\nqhgJNqBPOTEvvGvJNRoi39haEY3cuTqsxZ5FAlFlVFMUUozz+d0xBLLInoVY/Y4h\nhSdGmdw/A6oHodLqyEp3N5RZNdLlh8/nDS3xXzMotAl75bW5kc2ttcRhRdtyNJ9Z\nup0PgppO3QKBgEC45upAQz8iCiKkz+EA8C4FGqYQJcLHvmoC8GOcAioMqrKNoDVt\ns2cZbdChynEpcd0iQ058YrDnbZeiPWHgFnBp0Gf+gQI7+u8X2+oTDci0s7Au/YZJ\nuxB8YlUX8QF1clvqqzg8OVNzKy9UR5gm+9YyWVPjq5HfH6kOZx0nAxNjAoGAERt8\nqgsCC9/wxbKnpCC0oh3IG5N1WUdjTKh7sHfVN2DQ/LR+fHsniTDVg1gWbKBTDsty\nj7PWgC7ZiFxjKz45NtyX7LW4/efLFttdezsVhR500nnFMFseCdFy7Iu3afThHKfH\nehdj27RFSTqWBrAtFjsj+dzERcOCqIRwvwDe/cUCgYEA5+1mzVXDVjKsWylKJPk+\nZZA4LUfvmTj3VLNDZrlSAI/xEikCFio0QWEA2TQYTAwbXTrKwQSeHQRhv7OTc1h+\nMhpAgvs189ze5J4jiNmULEkkrO+Cxxnw8tyV+UFRZtzW9gUoVBwXiZ/Wbl9sfnlO\nwLJHc0j6OltPcPJmxHP8gQI=\n-----END PRIVATE KEY-----\n"),
			},
			res{
				code: 200,
				err:  false,
			},
		},
		{
			"certificate with key not connected",
			args{
				metadataEndpoint: "/saml/metadata",
				issuer:           "http://localhost:50002",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints:          &EndpointConfig{},
				},
				certificate: []byte("-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n"),
				key:         []byte("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC87EFxmmJArBYF\nQeMHwkINBIVeSPrS/RHsbFCMdOv/13hEq8uQJSml/TnJa76fgRZ6SRCCiRKbt/Js\nINaf8CUGeYuVpA50yhJNNeSKLGW+jETTsJZKJBFdPVT3Zma7SL7ND/DWvNsJ1oUe\nyMrxIWOFo/lPs71PDZaEHZ+0KBEDqGF+rBFn84TbViDoG1zo/i7ApkNMQn2EE4UT\ny0/omk1r1XWiOrh5qA951Swtgxf7B7tt21UeLzyqZmPb/RufFjzAiccFIM/QHEDU\nH/VJTHc6JokWQfJpAq1T86L+IdFFh2pA93ybftYouUCElQDHiOp83n9moKEHdkGs\nTJSiXHe/AgMBAAECggEBAIbzRHQ/0Xtc8YXj4KaELuZZmmMVQoZAW/NEE+2g/4uL\ngM+c4BYhVbTKQ+MLYelSLpo/Ytm7zF0LctGmS2mIAwqy+/Bydhka1yPsIUpKGIua\navfEJjbjuLufuffXX/7cId8dSe46jURjxkeNKto//XVTAh3ayJmVnTTWbGQmUrEG\n9KUz5Nc7d+Z7tqwPIQwiM3rg/XGymL7QD117QKBrZrqXSR9svcKSeqXm2rXUFzO2\n7SKOjspG5eB3wzGeRjC8ZakOpycLchZptvposYG4nNtKjmFScjD2Tb6uw+WjWTOt\nxCw5aF3QPvsmFu97PW9ih7rKNgLLDc0NS7HzPO/IiyECgYEA8kE995HNN1MYsB43\nXV3i3SLWywZUzSqof+ppcDyKtdFxGownPNFBtP4TDCUQBjFNf23xXjIb172gJI1a\nbi7AZ+Zwy9tCTh6l2T7F9dLdx7dlx4OA3jotnzbo/Jm4JWJPOe4kJSjB9pNlTHgY\nXDMl8lQKWx3Znud48hvvaIiBpWkCgYEAx6Rdf5vxFrHg/t8Cx4+55+1ifidIdnPb\n67mU+zO7pS0DEtrltKSPRcy3SIdS9sv60rO33b2pSJoPg/NWTmF1N9sRupJmmWTt\nW5Alux2c96asRevdEauyNNBRA8qI5EXJ2OIRg780imNfjpFQh4RSCzy2WGHWw98d\n40KK9dDJxucCgYEAo6Vc5dMxLJFOmRIgVkroyHcTX9xsBpgtcRN5nF7ZWM8dt1A7\n5UJ6P3huh4K122kMr+sl5Hq3AjrPZkGyd8HPKaCqS5tWpAzh/eoAsfl65cHG2ErG\nD9h/HxFpu9FfaqmJWVm8QvnQZO/WuxxZYFcQ6CzLPhfg/Q3iTrJ+PEASTBkCgYAu\nXSmpnRmcX6sVBc2rcuGFz0d0bMMTX0zPrcW/oQAPGCkCk/uMvDrZxvU5ztOhpTWX\nAU3OHWHXDpBT4ItGoLOMSUAQyDczoJDPFubsUbBGg1q20lQA6pL0WPy3mK259csu\npzHSGvGkwfdLMMw27K/xFCR02iP6UTKruKR0+gwiOQKBgDYDq7IeUoSWvHZAhGvp\nKPwk+oglrKim/UUW8UoJNPxTrII+8yjT/ZdV5MwwXujAtfGZUbpC4DpfZyDcsG9M\noReyieJAyoNbQKP8754/oVNx/Czz4V6baE4KSRJHu5wHQamCxgGiY41XI0l5XwLi\nlTFIxj9VXfhMdhBwIMTw4sGB\n-----END PRIVATE KEY-----\n"),
			},
			res{
				code: 200,
				err:  false,
			},
		},
		{
			"certificate with key empty",
			args{
				metadataEndpoint: "/saml/metadata",
				issuer:           "http://localhost:50002",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints:          &EndpointConfig{},
				},
				certificate: []byte("-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n"),
				key:         []byte(""),
			},
			res{
				code: 200,
				err:  false,
			},
		},
		{
			"key with certificate empty",
			args{
				metadataEndpoint: "/saml/metadata",
				issuer:           "http://localhost:50002",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints:          &EndpointConfig{},
				},
				certificate: []byte(""),
				key:         []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq\nVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc\nWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2\ngIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a\nEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7\nLfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v\n4cxTNPn/AgMBAAECggEAF+rV9yH30Ysza8GwrXCR9qDN1Dp3QmmsavnXkonEvPoq\nEr2T3o0//6mBp6CLDboMQGQBjblJwl+3Y6PgZolvHAMOsMdHfYNPEo7FSzUBzEw+\nqRrs5HkMyvoPgfV6X8F97W3tiD4Q/AmHkMILl+MxbnfPXM54gWqPuwIqxY1uaCk5\nREwyb7WBon3rd58ceOI1SLRjod6SbqWBMMSN3cJ+5VEPObFjw/RlhNQ5rBI8G5Kt\nso2zBU5C4BB2CvqlWy98WDKJkTvWHbiTjZCy8BQ+gQ6UJM2vaNELFOVpuMGQnMIi\noWiX10Jg2e1gP9j3TdrohlGF8M3+TXjSFKNmeX0DUQKBgQDx7UazUWS5RtkgnjH9\nw2xH2xkstJVD7nAS8VTxNwcrgjVXPvTJha9El904obUjyRX7ppb02tuH5ML/bZh6\n9lL4bP5+SHcJ10e4q8CK/KAGHD6BYAbaGXRq0CoSk5a3vv5XPdob4T5qKCIHFpnu\nMfbvdbEoameLOyRYOGu/yVZIiwKBgQDGQs7FRTisHV0xooiRmlvYF0dcd19qpLed\nqhgJNqBPOTEvvGvJNRoi39haEY3cuTqsxZ5FAlFlVFMUUozz+d0xBLLInoVY/Y4h\nhSdGmdw/A6oHodLqyEp3N5RZNdLlh8/nDS3xXzMotAl75bW5kc2ttcRhRdtyNJ9Z\nup0PgppO3QKBgEC45upAQz8iCiKkz+EA8C4FGqYQJcLHvmoC8GOcAioMqrKNoDVt\ns2cZbdChynEpcd0iQ058YrDnbZeiPWHgFnBp0Gf+gQI7+u8X2+oTDci0s7Au/YZJ\nuxB8YlUX8QF1clvqqzg8OVNzKy9UR5gm+9YyWVPjq5HfH6kOZx0nAxNjAoGAERt8\nqgsCC9/wxbKnpCC0oh3IG5N1WUdjTKh7sHfVN2DQ/LR+fHsniTDVg1gWbKBTDsty\nj7PWgC7ZiFxjKz45NtyX7LW4/efLFttdezsVhR500nnFMFseCdFy7Iu3afThHKfH\nehdj27RFSTqWBrAtFjsj+dzERcOCqIRwvwDe/cUCgYEA5+1mzVXDVjKsWylKJPk+\nZZA4LUfvmTj3VLNDZrlSAI/xEikCFio0QWEA2TQYTAwbXTrKwQSeHQRhv7OTc1h+\nMhpAgvs189ze5J4jiNmULEkkrO+Cxxnw8tyV+UFRZtzW9gUoVBwXiZ/Wbl9sfnlO\nwLJHc0j6OltPcPJmxHP8gQI=\n-----END PRIVATE KEY-----\n"),
			},
			res{
				code: 500,
				err:  false,
			},
		},
		{
			"certificate with key nil",
			args{
				metadataEndpoint: "/saml/metadata",
				issuer:           "http://localhost:50002",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints:          &EndpointConfig{},
				},
				certificate: []byte("-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQD6E8ZGsQ2usjANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwMjE3MTQwNjM5WhcNMjMwMjE3MTQw\nNjM5WjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XKdCRxUZXjdqVqwwwOJqc1Ch0nOSmk+U\nerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWcWAHJloqZ7GBS7NpDhzV8\nG+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2gIfsYPs3TTq1sq7oCs5q\nLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+aEkyRh07oMpXBEobGisfF\n2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7Lfgq7oxmv/8LFi4Zopr5\nnyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v4cxTNPn/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAJYxROWSOZbOzXzafdGjQKsMgN948G/hHwVuZneyAcVo\nLMFTs1Weya9Z+snMp1u0AdDGmQTS9zGnD7syDYGOmgigOLcMvLMoWf5tCQBbEukW\n8O7DPjRR0XypChGSsHsqLGO0B0HaTel0HdP9Si827OCkc9Q+WbsFG/8/4ToGWL+u\nla1WuLawozoj8umPi9D8iXCoW35y2STU+WFQG7W+Kfdu+2CYz/0tGdwVqNG4Wsfa\nwWchrS00vGFKjm/fJc876gAfxiMH1I9fZvYSAxAZ3sVI//Ml2sUdgf067ywQ75oa\nLSS2NImmz5aos3vuWmOXhILd7iTU+BD8Uv6vWbI7I1M=\n-----END CERTIFICATE-----\n"),
				key:         nil,
			},
			res{
				code: 500,
				err:  false,
			},
		},
		{
			"key with certificate nil",
			args{
				metadataEndpoint: "/saml/metadata",
				issuer:           "http://localhost:50002",
				config: &IdentityProviderConfig{
					SignatureAlgorithm: dsig.RSASHA256SignatureMethod,
					MetadataIDPConfig:  &MetadataIDPConfig{},
					Endpoints:          &EndpointConfig{},
				},
				certificate: nil,
				key:         []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7XKdCRxUZXjdq\nVqwwwOJqc1Ch0nOSmk+UerkUqlviWHdeLR+FolHKjqLzCBloAz4xVc0DFfR76gWc\nWAHJloqZ7GBS7NpDhzV8G+cXQ+bTU0Lu2e73zCQb30XUdKhWiGfDKaU+1xg9CD/2\ngIfsYPs3TTq1sq7oCs5qLdUHaVL5kcRaHKdnTi7cs5i9xzs3TsUnXcrJPwydjp+a\nEkyRh07oMpXBEobGisfF2p1MA6pVW2gjmywf7D5iYEFELQhM7poqPN3/kfBvU1n7\nLfgq7oxmv/8LFi4Zopr5nyqsz26XPtUy1WqTzgznAmP+nN0oBTERFVbXXdRa3k2v\n4cxTNPn/AgMBAAECggEAF+rV9yH30Ysza8GwrXCR9qDN1Dp3QmmsavnXkonEvPoq\nEr2T3o0//6mBp6CLDboMQGQBjblJwl+3Y6PgZolvHAMOsMdHfYNPEo7FSzUBzEw+\nqRrs5HkMyvoPgfV6X8F97W3tiD4Q/AmHkMILl+MxbnfPXM54gWqPuwIqxY1uaCk5\nREwyb7WBon3rd58ceOI1SLRjod6SbqWBMMSN3cJ+5VEPObFjw/RlhNQ5rBI8G5Kt\nso2zBU5C4BB2CvqlWy98WDKJkTvWHbiTjZCy8BQ+gQ6UJM2vaNELFOVpuMGQnMIi\noWiX10Jg2e1gP9j3TdrohlGF8M3+TXjSFKNmeX0DUQKBgQDx7UazUWS5RtkgnjH9\nw2xH2xkstJVD7nAS8VTxNwcrgjVXPvTJha9El904obUjyRX7ppb02tuH5ML/bZh6\n9lL4bP5+SHcJ10e4q8CK/KAGHD6BYAbaGXRq0CoSk5a3vv5XPdob4T5qKCIHFpnu\nMfbvdbEoameLOyRYOGu/yVZIiwKBgQDGQs7FRTisHV0xooiRmlvYF0dcd19qpLed\nqhgJNqBPOTEvvGvJNRoi39haEY3cuTqsxZ5FAlFlVFMUUozz+d0xBLLInoVY/Y4h\nhSdGmdw/A6oHodLqyEp3N5RZNdLlh8/nDS3xXzMotAl75bW5kc2ttcRhRdtyNJ9Z\nup0PgppO3QKBgEC45upAQz8iCiKkz+EA8C4FGqYQJcLHvmoC8GOcAioMqrKNoDVt\ns2cZbdChynEpcd0iQ058YrDnbZeiPWHgFnBp0Gf+gQI7+u8X2+oTDci0s7Au/YZJ\nuxB8YlUX8QF1clvqqzg8OVNzKy9UR5gm+9YyWVPjq5HfH6kOZx0nAxNjAoGAERt8\nqgsCC9/wxbKnpCC0oh3IG5N1WUdjTKh7sHfVN2DQ/LR+fHsniTDVg1gWbKBTDsty\nj7PWgC7ZiFxjKz45NtyX7LW4/efLFttdezsVhR500nnFMFseCdFy7Iu3afThHKfH\nehdj27RFSTqWBrAtFjsj+dzERcOCqIRwvwDe/cUCgYEA5+1mzVXDVjKsWylKJPk+\nZZA4LUfvmTj3VLNDZrlSAI/xEikCFio0QWEA2TQYTAwbXTrKwQSeHQRhv7OTc1h+\nMhpAgvs189ze5J4jiNmULEkkrO+Cxxnw8tyV+UFRZtzW9gUoVBwXiZ/Wbl9sfnlO\nwLJHc0j6OltPcPJmxHP8gQI=\n-----END PRIVATE KEY-----\n"),
			},
			res{
				code: 500,
				err:  false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := NewEndpoint(tt.args.metadataEndpoint)
			mockStorage := idpStorageWithResponseCert(t, tt.args.certificate, tt.args.key)
			if mockStorage == nil {
				return
			}

			idp, err := newTestIdentityProvider(endpoint, tt.args.config, mockStorage, tt.args.issuer)
			if (err != nil) != tt.res.err {
				t.Errorf("NewIdentityProvider() error = %v", err.Error())
				return
			}
			if idp == nil {
				return
			}

			req := httptest.NewRequest(http.MethodGet, idp.endpoints.certificateEndpoint.Relative(), nil)
			w := httptest.NewRecorder()

			callHandlerFuncWithIssuerInterceptor(idp.issuerFromRequest, w, req, idp.certificateHandleFunc)

			res := w.Result()
			defer func() {
				_ = res.Body.Close()
			}()
			data, err := ioutil.ReadAll(res.Body)
			if res.StatusCode != tt.res.code {
				t.Errorf("certificateHandleFunc() code got = %v, want %v", res.StatusCode, tt.res)
			}
			if res.StatusCode == http.StatusOK && string(data) != string(tt.args.certificate) {
				t.Errorf("certificateHandleFunc() count got = %v, want %v", string(data), tt.args.certificate)
			}
		})
	}
}

func newTestIdentityProvider(metadata Endpoint, conf *IdentityProviderConfig, storage IDPStorage, issuer string) (_ *IdentityProvider, err error) {
	idp, err := NewIdentityProvider(metadata, conf, storage)
	if err != nil {
		return nil, err
	}
	idp.issuerFromRequest, err = StaticIssuer(issuer)(true)
	if err != nil {
		return nil, err
	}
	return idp, nil
}

func idpStorageWithResponseCert(t *testing.T, cert []byte, pKey []byte) *mock.MockIDPStorage {
	mockStorage := mock.NewMockIDPStorage(gomock.NewController(t))
	certAndKey := &key.CertificateAndKey{
		Certificate: nil,
		Key:         nil,
	}

	if cert != nil {
		certBytes := make([]byte, 0)
		if len(cert) > 0 {
			blockCert, _ := pem.Decode(cert)
			if blockCert == nil || blockCert.Type != "CERTIFICATE" {
				t.Errorf("failed to parse certificate")
			}
			certBytes = blockCert.Bytes
		}
		certAndKey.Certificate = certBytes
	}

	if pKey != nil {
		priv := new(rsa.PrivateKey)
		if len(pKey) > 0 {
			blockKey, _ := pem.Decode(pKey)
			b := blockKey.Bytes
			privT, err := x509.ParsePKCS8PrivateKey(b)
			if err != nil {
				t.Errorf("failed to parse private key")
				return nil
			}
			priv = privT.(*rsa.PrivateKey)
		}
		certAndKey.Key = priv
	}

	mockStorage.EXPECT().GetResponseSigningKey(gomock.Any()).Return(certAndKey, nil).MinTimes(0).MaxTimes(1)
	return mockStorage
}

func callHandlerFuncWithIssuerInterceptor(issuer IssuerFromRequest, w http.ResponseWriter, r *http.Request, handlerFunc func(w http.ResponseWriter, r *http.Request)) {
	interceptor := NewIssuerInterceptor(issuer)

	intercepted := interceptor.HandlerFunc(handlerFunc)
	intercepted(w, r)
}
