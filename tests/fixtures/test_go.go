package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	_ = name

	cmd := r.FormValue("cmd")
	exec.Command("sh", "-c", cmd)
}
