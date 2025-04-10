package checker

import (
	"context"
	"fmt"
	"time"

	"github.com/yourusername/k8s-ssl-expiry-checker/internal"
)

func Run() error {
	clientset, err := internal.GetKubeClient()
	if err != nil {
		return fmt.Errorf("unable to create Kubernetes client: %w", err)
	}

	secrets, err := clientset.CoreV1().Secrets("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to list secrets: %w", err)
	}

	for _, secret := range secrets.Items {
		if secret.Type == "kubernetes.io/tls" {
			expiry, err := ParseCertExpiry(secret.Data["tls.crt"])
			if err != nil {
				continue
			}
			days := int(time.Until(expiry).Hours() / 24)
			if days < 30 {
				msg := fmt.Sprintf("⚠️ TLS cert in secret %s/%s expires in %d days (%s)", secret.Namespace, secret.Name, days, expiry)
				SendTelegram(msg)
			}
		}
	}
	return nil
}
