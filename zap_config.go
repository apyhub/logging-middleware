package logware

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func getLogger(serviceName string) (*zap.Logger, error) {
	zapLogger, err := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapcore.DebugLevel),
		Encoding:         "json",
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		InitialFields:    map[string]interface{}{"service": serviceName},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:    "msg",
			LevelKey:      "level",
			TimeKey:       "ts",
			CallerKey:     "caller",
			FunctionKey:   "function",
			StacktraceKey: "stackTrace",
			EncodeTime:    zapcore.ISO8601TimeEncoder,
			EncodeLevel:   zapcore.CapitalLevelEncoder,
			EncodeCaller:  zapcore.ShortCallerEncoder,
		},
	}.Build()
	if err != nil {
		return nil, err
	}
	return zapLogger, nil
}
