package utils

import "net/mail"

// ValidateEmail faz a validação do formato do e-mail digitado
func ValidMailAddress(address string) bool {
	if address == "" {
		return true
	}
	_, err := mail.ParseAddress(address)
	if err != nil {
		return false
	}
	return true
}
