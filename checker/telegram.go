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
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" {
		log.Println("Telegram credentials not set")
		return
	}

	tgURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := url.Values{}
	payload.Set("chat_id", chatID)
	payload.Set("text", message)

	resp, err := http.Post(tgURL, "application/x-www-form-urlencoded", strings.NewReader(payload.Encode()))
	if err != nil {
		log.Printf("failed to send Telegram message: %v", err)
		return
	}
	defer resp.Body.Close()
}
