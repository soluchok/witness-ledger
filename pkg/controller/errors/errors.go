package errors

import (
	"errors"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service errors.
const (
	ErrValidation = validationErr("validation failed")
	ErrInternal   = validationErr("internal error")
)

type validationErr string

func (e validationErr) Error() string {
	return string(e)
}

func (e validationErr) StatusCode() int {
	return http.StatusBadRequest
}

// StatusCodeFromError returns status code if an error implements an interface the func supports rpc errors as well.
func StatusCodeFromError(e error) int {
	if err, ok := e.(interface{ StatusCode() int }); ok { // nolint: errorlint
		return err.StatusCode()
	}

	rpcStatus, ok := status.FromError(e)
	if ok {
		return statusCodeFromRPCError(rpcStatus.Code())
	}

	if err := errors.Unwrap(e); err != nil {
		return StatusCodeFromError(err)
	}

	return http.StatusInternalServerError
}

func statusCodeFromRPCError(rpcCode codes.Code) int {
	switch rpcCode { // nolint: exhaustive
	case codes.OK:
		return http.StatusOK
	case codes.Canceled, codes.DeadlineExceeded:
		return http.StatusRequestTimeout
	case codes.InvalidArgument, codes.OutOfRange, codes.AlreadyExists:
		return http.StatusBadRequest
	case codes.NotFound:
		return http.StatusNotFound
	case codes.PermissionDenied, codes.ResourceExhausted:
		return http.StatusForbidden
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.FailedPrecondition:
		return http.StatusPreconditionFailed
	case codes.Aborted:
		return http.StatusConflict
	case codes.Unimplemented:
		return http.StatusNotImplemented
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
