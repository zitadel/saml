package models

type AuthRequestInt interface {
	GetID() string
	GetApplicationID() string
	GetRelayState() string
	GetAccessConsumerServiceURL() string
	GetBindingType() string
	GetAuthRequestID() string
	GetIssuer() string
	GetDestination() string
	GetUserID() string
	Done() bool
}

type AttributeSetter interface {
	SetEmail(string)
	SetFullName(string)
	SetGivenName(string)
	SetSurname(string)
	SetUserID(string)
	SetUsername(string)
	SetCustomAttribute(name string, friendlyName string, nameFormat string, attributeValue []string)
}
