package main

import (
	"fmt"
	"os"
	"testing"
)

func TestOs(t *testing.T) {
	gopath := os.Getenv("GOPATH")
	fmt.Println(gopath)
}
