package logware

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sync"
)

var (
	zapLogger *zap.Logger
	err       error
	once      sync.Once
)

// getLogger calls the initZap() once, initiate the zap logger and returns it.
func getLogger(serviceName string) *zap.Logger {
	once.Do(func() {
		err := initZap(serviceName)
		if err != nil {
			panic("Failed to initialize logger: " + err.Error())
		}
	})
	return zapLogger
}

func initZap(serviceName string) error {
	if zapLogger != nil {
		return nil
	}
	zapLogger, err = zap.Config{
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
		return err
	}
	zap.ReplaceGlobals(zapLogger)
	return nil
}
