// Package web embeds the browser interface: templates and static assets.
package web

import "embed"

// FS holds templates/ and static/.
//
//go:embed templates static
var FS embed.FS
