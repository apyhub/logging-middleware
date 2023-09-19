package logware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"runtime"
	"strconv"
	"strings"
)

const CustomBufferSize = 100 * 1024 * 1024

var ignoredHeaders = map[string]struct{}{
	"X-Consumer-Id":       {},
	"X-Consumer-Username": {},
}

func Logging(serviceName string) mux.MiddlewareFunc {
	logger := getLogger(serviceName)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			customRW := &customResponseWriter{
				ResponseWriter: w,
				LogData:        logData{},
			}

			customRW.LogData.Request.Headers = make(map[string][]string)
			for key, value := range r.Header {
				if _, exists := ignoredHeaders[key]; !exists {
					customRW.LogData.Request.Headers[key] = value
				}
			}
			if urlQuery := r.URL.Query(); len(urlQuery) > 0 {
				customRW.LogData.Request.Query = urlQuery
			}
			contentType := r.Header.Get("Content-Type")
			if isStringRepresent(contentType) {
				if err := customRW.LogData.Request.inspectJsonData(r); err != nil {
					http.Error(w, "Failed to read request Body", http.StatusInternalServerError)
					return
				}
			} else if strings.HasPrefix(contentType, "multipart/form-data") {
				if err := customRW.LogData.Request.inspectMultipartForm(r); err != nil {
					http.Error(w, "Failed to read request Body", http.StatusInternalServerError)
					return
				}
			}
			customRW.LogData.URL = r.URL.Path
			traceId := uuid.New()
			ctx := context.WithValue(r.Context(), "trace_id", traceId.String())
			customRW.LogData.TraceId = traceId.String()
			next.ServeHTTP(customRW, r.WithContext(ctx))
			logger.Info("SERVICE LOG", zap.Any("data", customRW.getFormattedLog()))
		})
	}
}

type logData struct {
	URL        string       `json:"url"`
	TraceId    string       `json:"trace_id"`
	StatusCode int          `json:"status_code"`
	Message    string       `json:"message"`
	Error      string       `json:"error"`
	StackTrace []string     `json:"stack_trace,omitempty"`
	Request    requestData  `json:"request"`
	Response   responseData `json:"response"`
}

// *************** Request ********************
type requestData struct {
	FormData map[string]interface{} `json:"form_data,omitempty"`
	Query    map[string][]string    `json:"query_data"`
	Body     []byte                 `json:"body,omitempty"`    // For saving request Body
	Headers  map[string][]string    `json:"headers,omitempty"` // For saving request Headers
}

func getLogPart(key string, value []byte) string {
	if len(value) > 0 {
		return fmt.Sprintf(`%s: %s`, key, value)
	}
	return ""
}

func (rq *requestData) formatLog() string {
	var logString []string
	if rq.Query != nil {
		queryData, _ := json.Marshal(rq.Query)
		logString = append(logString, getLogPart(`"query"`, queryData))
	}
	if rq.Headers != nil {
		headers, _ := json.Marshal(rq.Headers)
		logString = append(logString, getLogPart(`"headers"`, headers))
	}
	if rq.FormData != nil {
		formData, _ := json.Marshal(rq.FormData)
		logString = append(logString, getLogPart(`"form"`, formData))
	}
	if len(rq.Body) > 0 {
		// not converting r.Body to json because we're not sure what the body will be
		if !isJson(rq.Headers["Content-Type"][0]) {
			logString = append(logString, getLogPart(`"body"`, getQuotedOrJson(rq.Body)))
		} else {
			var requestBody map[string]interface{}
			if err := json.Unmarshal(rq.Body, &requestBody); err != nil {
				log.Output(1, "invalid json - request body cannot be unmarshalled")
				logString = append(logString, getLogPart(`"body"`, getQuotedOrJson(rq.Body)))
			} else {
				logString = append(logString, getLogPart(`"body"`, rq.Body))
			}
		}
	}
	return fmt.Sprintf("%s", strings.Join(logString, ","))
}

func (rq *requestData) inspectMultipartForm(r *http.Request) error {

	// Ensure it's a multipart form
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		return errors.New("not a multipart/form-data request")
	}

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(reqBody))

	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return err
	}
	limitedReader := &customLimitedReader{
		R: bytes.NewReader(reqBody),
		N: CustomBufferSize,
	}

	mr := multipart.NewReader(limitedReader, params["boundary"])

	rq.FormData = make(map[string]interface{})

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// If it's a file, capture the filename.
		if part.FileName() != "" {
			rq.FormData[part.FormName()] = part.FileName()
		} else {
			// Else, read the form field's value
			fieldValue, err := io.ReadAll(part)
			if err != nil {
				return err
			}
			rq.FormData[part.FormName()] = fieldValue
		}
		part.Close()
	}
	return nil
}

func (rq *requestData) inspectJsonData(r *http.Request) error {
	// Capture the request Body
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	rq.Body = reqBody

	// Since we've read the Body, replace the r.Body with the saved data
	r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
	return nil
}

// *************** Response ********************
// embedding the http.ResponseWriter in the customResponseWriter.
// variables of type customResponseWriter will have access to all the methods/attributes of http.ResponseWriter
type customResponseWriter struct {
	http.ResponseWriter
	LogData logData
}

type responseData struct {
	Body    []byte              `json:"Body"`
	Headers map[string][]string `json:"Headers"`
}

func (r *responseData) formatLog() string {
	var logString []string
	if r.Headers != nil {
		headers, _ := json.Marshal(r.Headers)
		logString = append(logString, getLogPart(`"headers"`, headers))
	}

	if r.Body != nil {
		if r.Headers["Content-Type"] == nil || !isJson(r.Headers["Content-Type"][0]) {
			logString = append(logString, getLogPart(`"body"`, getQuotedOrJson(r.Body)))
		} else {
			logString = append(logString, fmt.Sprintf(`"body": %s`, r.Body))
		}
	}

	//return fmt.Sprintf("\n\t\t%s\n", strings.Join(logString, ",\n\t\t"))
	return fmt.Sprintf("%s", strings.Join(logString, ","))
}

// overriding the WriteHeader method of http.ResponseWriter
func (rw *customResponseWriter) WriteHeader(statusCode int) {
	rw.LogData.StatusCode = statusCode
	rw.LogData.Message = http.StatusText(rw.LogData.StatusCode)
	rw.ResponseWriter.WriteHeader(statusCode)
}

// overriding the Write method of http.ResponseWriter
func (rw *customResponseWriter) Write(b []byte) (int, error) {
	rw.LogData.Response.Headers = rw.ResponseWriter.Header()
	contentType := rw.ResponseWriter.Header().Get("Content-Type")
	if strings.TrimSpace(contentType) != "" {
		if isStringRepresent(contentType) {
			rw.LogData.Response.Body = b
		} else {
			rw.LogData.Response.Body = []byte(contentType + " data")
		}
	} else {
		rw.LogData.Response.Body = []byte(UnknownContentType)
	}

	if !(200 <= rw.LogData.StatusCode && rw.LogData.StatusCode <= 299) {
		stackTrace := strings.Split(strings.ReplaceAll(captureStackTrace(), "\t", ""), "\n")
		rw.LogData.StackTrace = stackTrace[:len(stackTrace)-1]
	}
	return rw.ResponseWriter.Write(b)
}

func (rw *customResponseWriter) writeError(err error) {
	rw.LogData.Error = strings.Replace(err.Error(), `"`, `'`, -1)
}

func (rw *customResponseWriter) getFormattedLog() map[string]interface{} {
	// todo - formatted log for
	var formattedLogSlice []string
	formattedLogSlice = append(formattedLogSlice, fmt.Sprintf(`"url": "%s"`, rw.LogData.URL))
	formattedLogSlice = append(formattedLogSlice, fmt.Sprintf(`"trace_id": "%s"`, rw.LogData.TraceId))
	formattedLogSlice = append(formattedLogSlice, fmt.Sprintf(`"status": "%s"`, strconv.Itoa(rw.LogData.StatusCode)))
	formattedLogSlice = append(formattedLogSlice, fmt.Sprintf(`"message": "%s"`, rw.LogData.Message))
	if len(rw.LogData.StackTrace) > 0 {
		stackTraceJson, err := json.Marshal(rw.LogData.StackTrace)
		if err != nil {
			log.Output(1, fmt.Sprintf("error in unmarshalling stackTrace: %s", err.Error()))
		}
		formattedLogSlice = append(formattedLogSlice, fmt.Sprintf(`"stack_trace": %s`, stackTraceJson))
	}
	if strings.TrimSpace(rw.LogData.Error) != "" {
		formattedLogSlice = append(formattedLogSlice, fmt.Sprintf(`"error": "%s"`, rw.LogData.Error))
	}
	formattedLogSlice = append(formattedLogSlice, fmt.Sprintf(`"request": {%s}`, rw.LogData.Request.formatLog()))
	formattedLogSlice = append(formattedLogSlice, fmt.Sprintf(`"response": {%s}`, rw.LogData.Response.formatLog()))
	//formattedLog := fmt.Sprintf("\n{\n\t%s\n}", strings.Join(formattedLogSlice, ",\n\t"))
	formattedLog := fmt.Sprintf("{%s}", strings.Join(formattedLogSlice, ","))

	var result map[string]interface{}
	err := json.Unmarshal([]byte(formattedLog), &result)
	if err != nil {
		log.Output(1, fmt.Sprintf("error in unmarshalling formattedLog: %s", err.Error()))
		return nil
	}

	return result
}

func isStringRepresent(contentType string) bool {
	availableContentTypes := []string{
		"text/plain",
		"text/html",
		"text/css",
		"text/xml",
		"application/xml",
		"application/javascript",
		"application/x-www-form-urlencoded",
		"application/json",
		"application/vnd.api+json",
		"application/hal+json",
		"application/graphql",
	}
	for _, availableContentType := range availableContentTypes {
		if strings.HasPrefix(contentType, availableContentType) {
			return true
		}
	}
	return false
}

func isJson(contentType string) bool {
	availableContentTypes := []string{
		"application/json",
		"application/vnd.api+json",
		"application/hal+json",
	}
	for _, availableContentType := range availableContentTypes {
		if strings.HasPrefix(contentType, availableContentType) {
			return true
		}
	}
	return false
}

type customLimitedReader struct {
	R io.Reader // underlying reader
	N int64     // max bytes remaining
}

func (l *customLimitedReader) Read(p []byte) (n int, err error) {
	if l.N <= 0 {
		return 0, errors.New("read limit exceeded")
	}
	if int64(len(p)) > l.N {
		p = p[0:l.N]
	}
	n, err = l.R.Read(p)
	l.N -= int64(n)
	return
}

func captureStackTrace() string {
	bufSize := 1024
	for {
		buf := make([]byte, bufSize)
		n := runtime.Stack(buf, false)
		if n < bufSize {
			return string(buf[:n])
		}
		bufSize *= 2
	}
}

func getQuotedOrJson(data []byte) []byte {
	// Check if data is already a valid JSON string
	log.Output(1, "getQuotedOrJson triggered")
	var temp interface{}
	bodyData := data
	if err := json.Unmarshal(bodyData, &temp); err != nil {
		// Not a valid JSON, quote it
		bodyData = []byte(strconv.Quote(string(data)))
	}
	return bodyData
}

// CaptureError accepts responseWriter interface and error(should not be nil).
//
// Attaches the error to the response logger (logware)
func CaptureError(w http.ResponseWriter, err error) error {
	if crw, ok := w.(*customResponseWriter); ok {
		if err != nil {
			crw.writeError(err)
		} else {
			return fmt.Errorf("err cannot be nil")
		}
	} else {
		return fmt.Errorf("invalid response writer. Logware is not used as middleware")
	}
	return nil
}
