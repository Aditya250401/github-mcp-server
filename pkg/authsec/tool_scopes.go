package authsec

import "github.com/github/github-mcp-server/pkg/inventory"

// ToolScopesFromInventory converts the GitHub MCP inventory into the simpler
// tool->accepted-scope map expected by the generic AuthSec SDK. AcceptedScopes
// are preferred because they already include scope hierarchy expansions such as
// "repo" satisfying "public_repo".
func ToolScopesFromInventory(inv *inventory.Inventory) map[string][]string {
	result := make(map[string][]string)
	for _, tool := range inv.AllTools() {
		switch {
		case len(tool.AcceptedScopes) > 0:
			result[tool.Tool.Name] = append([]string(nil), tool.AcceptedScopes...)
		case len(tool.RequiredScopes) > 0:
			result[tool.Tool.Name] = append([]string(nil), tool.RequiredScopes...)
		default:
			result[tool.Tool.Name] = []string{}
		}
	}
	return result
}
