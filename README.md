# SAML SDK (server) for Go

[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Release](https://github.com/zitadel/saml/workflows/Release/badge.svg)](https://github.com/zitadel/saml/actions)
[![license](https://badgen.net/github/license/zitadel/saml/)](https://github.com/zitadel/saml/blob/master/LICENSE)
[![release](https://badgen.net/github/release/zitadel/saml/stable)](https://github.com/zitadel/saml/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/zitadel/saml)](https://goreportcard.com/report/github.com/zitadel/saml)
[![codecov](https://codecov.io/gh/zitadel/saml/branch/master/graph/badge.svg)](https://codecov.io/gh/zitadel/saml)

## What is it

This project is a server implementation for the Security Assertion Markup Language (SAML) standard written for `Go`.

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

Supported SAML features:

| Feature | Identity provider |
| --- | --- | 
| POST-binding | yes |
| Redirect-binding | yes |
| Artifact-binding | [no](https://github.com/zitadel/zitadel/issues/3089) |
| Request signing | yes |
| Response signing | yes |
| Metadata signing | yes |
| Response encryption | [no](https://github.com/zitadel/zitadel/issues/3090) |
| Assertion Query/Request | no |
| Attribute Query | yes |
| NameID Mapping | no |

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

For security reasons, we only support and recommend the use of one of the latest three Go versions (:white_check_mark:)
.  
Versions that also build are marked with :warning:.

| Version | Supported          |
|---------|--------------------|
| <1.19   | :x:                |
| 1.19    | :warning:          |
| 1.20    | :warning:          |
| 1.21    | :warning:          |
| 1.22    | :white_check_mark: |
| 1.23    | :white_check_mark: |

## Why another library

As of 2021 there are only few `SAML` libraries, written in `Go`, which handle server and client implementations. As
maintainer of [github.com/zitadel/zitadel](https://github.com/zitadel/zitadel) we are strongly committed to the general
field of IAM (Identity and Access Management) and as such, we need solid frameworks to implement services.

The existing libraries that we evaluated were not implementing the standard strictly. For that reason we developed this
project to be compliant to the standard, while still having the possibility to handle outliers.

For signing and signature verification other already existing implementations
like `github.com/russellhaering/goxmldsig`(for POST-binding)
and `github.com/amdonov/xmlsig`(for redirect-binding).

## Other SAML libraries

[https://github.com/crewjam/saml](https://github.com/crewjam/saml)

Supports both IDP and SP side, whereas the IDP side is by their own definition only rudimentary.

[https://github.com/russellhaering/gosaml2](https://github.com/russellhaering/gosaml2)

Implementation of SP side with no IDP side, works with a lot of identity providers, also has an implementation of the
XML signing which is used in this library.

[https://github.com/RobotsAndPencils/go-saml](https://github.com/RobotsAndPencils/go-saml)

Only SP side, developed for several specific integrations with different IDPs, not an implementation for general SAML.

[https://github.com/amdonov/lite-idp](https://github.com/amdonov/lite-idp)

Basic implementation of IDP side more as a standalone service, not that good to integrate into existing product.

## License

The full functionality of this library is and stays open source and free to use for everyone. Visit
our [website](https://zitadel.com) and get in touch.

See the exact licensing terms [here](./LICENSE)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.

