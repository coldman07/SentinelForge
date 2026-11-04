package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed dist
var assets embed.FS

func Handler() http.Handler {
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		panic("embedded dashboard assets are unavailable: " + err.Error())
	}
	return http.FileServer(http.FS(dist))
}
