// The revision of the Model Context Protocol this server implements, named
// once.
//
// It lives in a module of its own because two places need it and they must
// not need one another: the MCP endpoint (mcp.ts) serves the revision, and an
// MCP export entry (exports.ts) names the revisions it offers. Importing one
// from the other would make a cycle, and declaring it twice would let the
// endpoint and the capability come to disagree about which revision this
// server speaks.
export const MCP_PROTOCOL_VERSION = "2026-07-28";
