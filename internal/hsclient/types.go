package hsclient

import "time"

// All uint64 identifiers are kept as opaque strings end-to-end: headscale's
// grpc-gateway serializes them as JSON strings, and parsing them into numbers
// would risk precision loss above 2^53 when the values round-trip through
// JavaScript.

// User mirrors v1User.
type User struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	CreatedAt     *time.Time `json:"createdAt,omitempty"`
	DisplayName   string     `json:"displayName,omitempty"`
	Email         string     `json:"email,omitempty"`
	ProviderID    string     `json:"providerId,omitempty"`
	Provider      string     `json:"provider,omitempty"`
	ProfilePicURL string     `json:"profilePicUrl,omitempty"`
}

// PreAuthKey mirrors v1PreAuthKey. Key holds the full secret only in the
// response of CreatePreAuthKey; keys are bcrypt-hashed at rest since
// headscale 0.28, so listings carry only a prefix.
type PreAuthKey struct {
	User       *User      `json:"user,omitempty"`
	ID         string     `json:"id"`
	Key        string     `json:"key,omitempty"`
	Reusable   bool       `json:"reusable"`
	Ephemeral  bool       `json:"ephemeral"`
	Used       bool       `json:"used"`
	Expiration *time.Time `json:"expiration,omitempty"`
	CreatedAt  *time.Time `json:"createdAt,omitempty"`
	ACLTags    []string   `json:"aclTags,omitempty"`
}

// Node mirrors v1Node. Route state lives here since headscale 0.26:
// AvailableRoutes is what the node advertises, ApprovedRoutes what an admin
// approved, SubnetRoutes the intersection currently served.
type Node struct {
	ID              string      `json:"id"`
	MachineKey      string      `json:"machineKey,omitempty"`
	NodeKey         string      `json:"nodeKey,omitempty"`
	DiscoKey        string      `json:"discoKey,omitempty"`
	IPAddresses     []string    `json:"ipAddresses,omitempty"`
	Name            string      `json:"name,omitempty"`
	User            *User       `json:"user,omitempty"`
	LastSeen        *time.Time  `json:"lastSeen,omitempty"`
	Expiry          *time.Time  `json:"expiry,omitempty"`
	PreAuthKey      *PreAuthKey `json:"preAuthKey,omitempty"`
	CreatedAt       *time.Time  `json:"createdAt,omitempty"`
	RegisterMethod  string      `json:"registerMethod,omitempty"`
	GivenName       string      `json:"givenName,omitempty"`
	Online          bool        `json:"online"`
	ApprovedRoutes  []string    `json:"approvedRoutes,omitempty"`
	AvailableRoutes []string    `json:"availableRoutes,omitempty"`
	SubnetRoutes    []string    `json:"subnetRoutes,omitempty"`
	Tags            []string    `json:"tags,omitempty"`
}

// Register methods as serialized by v1RegisterMethod.
const (
	RegisterMethodUnspecified = "REGISTER_METHOD_UNSPECIFIED"
	RegisterMethodAuthKey     = "REGISTER_METHOD_AUTH_KEY"
	RegisterMethodCLI         = "REGISTER_METHOD_CLI"
	RegisterMethodOIDC        = "REGISTER_METHOD_OIDC"
)

// APIKey mirrors v1ApiKey. The full secret is returned only by CreateAPIKey.
type APIKey struct {
	ID         string     `json:"id"`
	Prefix     string     `json:"prefix"`
	Expiration *time.Time `json:"expiration,omitempty"`
	CreatedAt  *time.Time `json:"createdAt,omitempty"`
	LastSeen   *time.Time `json:"lastSeen,omitempty"`
}

// CreateUserRequest mirrors v1CreateUserRequest.
type CreateUserRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	PictureURL  string `json:"pictureUrl,omitempty"`
}

// CreatePreAuthKeyRequest mirrors v1CreatePreAuthKeyRequest. User is the
// numeric user ID serialized as a string.
type CreatePreAuthKeyRequest struct {
	User       string     `json:"user"`
	Reusable   bool       `json:"reusable,omitempty"`
	Ephemeral  bool       `json:"ephemeral,omitempty"`
	Expiration *time.Time `json:"expiration,omitempty"`
	ACLTags    []string   `json:"aclTags,omitempty"`
}

// DebugCreateNodeRequest mirrors v1DebugCreateNodeRequest.
type DebugCreateNodeRequest struct {
	User   string   `json:"user"`
	Key    string   `json:"key"`
	Name   string   `json:"name"`
	Routes []string `json:"routes,omitempty"`
}

// Policy is the result of GetPolicy. UpdatedAt is nil in file mode.
type Policy struct {
	Policy    string     `json:"policy"`
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
}

// Health mirrors v1HealthResponse.
type Health struct {
	DatabaseConnectivity bool `json:"databaseConnectivity"`
}
