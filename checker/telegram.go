package checker

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func SendTelegram(message string) {
	const telegramLimit = 4096 // Telegram's message size limit

	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" {
		log.Println("Telegram credentials not set")
		return
	}

	tgURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	for i := 0; i < len(message); i += telegramLimit {
		end := i + telegramLimit
		if end > len(message) {
			end = len(message)
		}

		chunk := message[i:end]

		payload := url.Values{}
		payload.Set("chat_id", chatID)
		payload.Set("text", chunk)

		resp, err := http.Post(tgURL, "application/x-www-form-urlencoded", strings.NewReader(payload.Encode()))
		if err != nil {
			log.Printf("failed to send Telegram message chunk: %v", err)
			continue
		}
		resp.Body.Close()
	}
}
