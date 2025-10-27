package logger

import (
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
)

func InitStdoutLogger(prefix string) (zerolog.Logger, error) {
	log := zerolog.New(os.Stdout).With().Str("app", prefix).Timestamp().Logger()
	return log, nil
}

func InitFileLogger(prefix string) (zerolog.Logger, error) {
	// generate filename with prefix and add timestamp in temporary directory
	timeStamp := time.Now().Format("20060102_150405")
	fileName := prefix + "_" + timeStamp + ".log"
	logFilePath := filepath.Join(os.TempDir(), fileName)
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return zerolog.Logger{}, err
	}
	fileLogger := zerolog.New(file).With().Str("app", prefix).Timestamp().Logger()
	return fileLogger, nil
}
