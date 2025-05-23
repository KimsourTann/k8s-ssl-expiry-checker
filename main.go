package main

import (
	"log"
	"os"

	"github.com/KimsourTann/k8s-ssl-expiry-checker/checker"
)

func main() {
	// Load environment variables from .env file
	// err := godotenv.Load("config.env")
	// if err != nil {
	// 	log.Fatalf("Error loading config.env file")
	// }

	// Print out environment variables to verify
	log.Printf("TELEGRAM_BOT_TOKEN: %s", os.Getenv("TELEGRAM_BOT_TOKEN"))
	log.Printf("TELEGRAM_CHAT_ID: %s", os.Getenv("TELEGRAM_CHAT_ID"))

	if err := checker.Run(); err != nil {
		log.Fatalf("[fatal] %v", err)
	}
}
