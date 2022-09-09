# SAML SDK (server) for Go

[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Release](https://github.com/zitadel/saml/workflows/Release/badge.svg)](https://github.com/zitadel/saml/actions)
[![license](https://badgen.net/github/license/zitadel/saml/)](https://github.com/zitadel/saml/blob/master/LICENSE)
[![release](https://badgen.net/github/release/zitadel/saml/stable)](https://github.com/zitadel/saml/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/zitadel/saml)](https://goreportcard.com/report/github.com/zitadel/saml)
[![codecov](https://codecov.io/gh/zitadel/saml/branch/master/graph/badge.svg)](https://codecov.io/gh/zitadel/saml)

## What is it

This project is a server implementation for the "SAML" (Security Assertion Markup Language) standard written for `Go`.

For signing and signature verification other already existing implementations like `github.com/russellhaering/goxmldsig`
and `github.com/amdonov/xmlsig`.

## Basic Overview

The most important packages of the library:
<pre>
/pkg
    /provider definitions and implementation of a SAML provider (Identity provider)
        /serviceprovider definitions and implementation of a SAML user (Service provider)
        /xml definitions of SAML xml messages
        /checker helper to abstract the SAML standard in the processes
        /signature implementation to handle and create SAML signature
</pre>

## Features

|                   | POST-binding | Redirect-binding | Artifact-binding | Request signing | Response signing | Metadata signing | Response encryption | Assertion Query/Request | Attribute Query | NameID Mapping |
|-------------------|--------------|------------------|------------------|-----------------|------------------|---------|--------------------|-------------------------|-----------------|----------------|
| Identity provider | yes          | yes              | no               | yes             | yes              | yes              | no                | no                      | yes             | no             |

## Resources

For your convenience you can find the relevant standards linked below.

- [Security Assertion Markup Language (SAML) V2.0 Technical Overview](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [Assertions and Protocols for the OASIS Security Assertion Markup Language (SAML) V2.0 – Errata Composite](https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf)
- [Bindings for the OASIS Security Assertion Markup Language (SAML) V2.0 – Errata Composite](https://www.oasis-open.org/committees/download.php/35387/sstc-saml-bindings-errata-2.0-wd-05-diff.pdf)
- [Profiles for the OASIS Security Assertion Markup Language (SAML) V2.0 – Errata Composite](https://www.oasis-open.org/committees/download.php/35389/sstc-saml-profiles-errata-2.0-wd-06-diff.pdf)
- [Metadata for the OASIS Security Assertion Markup Language (SAML) V2.0 – Errata Composite](https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf)
- [Conformance Requirements for the OASIS Security Assertion Markup Language (SAML) V2.0 – Errata Composite](https://www.oasis-open.org/committees/download.php/35393/sstc-saml-conformance-errata-2.0-wd-04-diff.pdf)
- [xml.com SAML Specifications](http://saml.xml.org/saml-specifications)
- [SAML Developer Tools from Onelogin](https://www.samltool.com/online_tools.php)

## Supported Go Versions

For security reasons, we only support and recommend the use of one of the latest two Go versions (:white_check_mark:).  
Versions that also build are marked with :warning:.

| Version | Supported          |
|---------|--------------------|
| <1.15   | :x:                |
| 1.15    | :warning:          |
| 1.16    | :warning:          |
| 1.17    | :white_check_mark: |
| 1.18    | :white_check_mark: |
| 1.19    | :white_check_mark: |

## Why another library

As of 2021 there are not a lot of `SAML` library's in `Go` which can handle server and client implementations. CAOS is
strongly committed to the general field of IAM (Identity and Access Management) and as such, we need solid frameworks to
implement services.

There are some implementations around not specificly after the standard, so the library has to have the possibility to
provide the functionality to
still include the outliers.

## License

The full functionality of this library is and stays open source and free to use for everyone. Visit
our [website](https://zitadel.com) and get in touch.

See the exact licensing terms [here](./LICENSE)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.

