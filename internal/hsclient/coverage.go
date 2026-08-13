package hsclient

// CoveredOperations enumerates every headscale API operation this client
// implements, as "METHOD /api/v1/..." with swagger-style path templates.
// The contract test asserts this list matches the pinned
// testdata/headscale-v0.29.3.swagger.json exactly — both directions — so the
// client can never silently drift from the spec (or claim coverage it does
// not have).
func CoveredOperations() []string {
	return []string{
		// Users
		"GET /api/v1/user",                           // ListUsers
		"POST /api/v1/user",                          // CreateUser
		"POST /api/v1/user/{oldId}/rename/{newName}", // RenameUser
		"DELETE /api/v1/user/{id}",                   // DeleteUser
		// PreAuthKeys
		"POST /api/v1/preauthkey",        // CreatePreAuthKey
		"GET /api/v1/preauthkey",         // ListPreAuthKeys
		"POST /api/v1/preauthkey/expire", // ExpirePreAuthKey
		"DELETE /api/v1/preauthkey",      // DeletePreAuthKey
		// Nodes
		"GET /api/v1/node",                            // ListNodes
		"GET /api/v1/node/{nodeId}",                   // GetNode
		"DELETE /api/v1/node/{nodeId}",                // DeleteNode
		"POST /api/v1/node/{nodeId}/expire",           // ExpireNode
		"POST /api/v1/node/{nodeId}/rename/{newName}", // RenameNode
		"POST /api/v1/node/{nodeId}/tags",             // SetTags
		"POST /api/v1/node/{nodeId}/approve_routes",   // SetApprovedRoutes
		"POST /api/v1/node/register",                  // RegisterNode (legacy)
		"POST /api/v1/node/backfillips",               // BackfillNodeIPs
		"POST /api/v1/debug/node",                     // DebugCreateNode
		// Auth flow (0.29)
		"POST /api/v1/auth/register", // AuthRegister
		"POST /api/v1/auth/approve",  // AuthApprove
		"POST /api/v1/auth/reject",   // AuthReject
		// API keys
		"POST /api/v1/apikey",            // CreateAPIKey
		"GET /api/v1/apikey",             // ListAPIKeys
		"POST /api/v1/apikey/expire",     // ExpireAPIKey
		"DELETE /api/v1/apikey/{prefix}", // DeleteAPIKey
		// Policy
		"GET /api/v1/policy",        // GetPolicy
		"PUT /api/v1/policy",        // SetPolicy
		"POST /api/v1/policy/check", // CheckPolicy
		// Health
		"GET /api/v1/health", // Health
	}
}
