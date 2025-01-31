package main

import (
	"os/exec"
)

func main() {
	_, err := exec.Command("dig", "-p", "2054", "datatracker.ietf.com", "+noedns").Output()
	if err != nil {
		panic(err)
	}
}
