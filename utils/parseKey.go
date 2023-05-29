package utils

import (
	"fmt"
	"strconv"
	"time"
)

// ParseKeyDuration faz o `parse` da duração das chaves convertendo os valores em dias, semanas, mês e ano. Analisando
func ParseKeyDuration(durationKey string) (time.Time, error) {
	if durationKey == "" {
		return time.Now(), nil
	}

	unidade := string(durationKey[len(durationKey)-1])
	durationStr := durationKey[:len(durationKey)-1]

	duration, err := strconv.Atoi(durationStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("Error occurred while getting duration")
	}

	switch unidade {
	case "d":
		return time.Now().AddDate(0, 0, duration), nil
	case "w":
		return time.Now().AddDate(0, 0, duration*7), nil
	case "m":
		return time.Now().AddDate(0, duration, 0), nil
	case "y":
		return time.Now().AddDate(duration, 0, 0), nil
	default:
		return time.Now(), fmt.Errorf("Error occurred while getting duration time key")
	}
}
