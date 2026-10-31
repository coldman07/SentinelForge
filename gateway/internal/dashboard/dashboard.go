package dashboard

import (
	"embed"
	"net/http"
)

//go:embed index.html
var assets embed.FS

func Handler() http.Handler {
	return http.FileServer(http.FS(assets))
}
