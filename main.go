package main

import (
	"log"

	"github.com/yourusername/k8s-ssl-expiry-checker/checker"
)

func main() {
	err := checker.Run()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}
