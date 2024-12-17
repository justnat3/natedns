package main

import (
	"os/exec"
)

func main() {
	_, err := exec.Command("dig", "-p", "2054", "google.com").Output()
	if err != nil {
		panic(err)
	}
}
