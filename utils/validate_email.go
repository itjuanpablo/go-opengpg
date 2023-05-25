package utils

import "regexp"

// ValidateEmail faz a validação do formato do e-mail digitado
func ValidateEmail(email string) bool {
	// Expressão regular para validar o formato do e-mail
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	match, _ := regexp.MatchString(emailRegex, email)
	return match
}
