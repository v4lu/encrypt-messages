package errs

import (
	"fmt"
	"net/http"

	"github.com/valu/encrpytion/pkg/jsn"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

type ErrorResponseWithDetails struct {
	Error   string                 `json:"error"`
	Details map[string]interface{} `json:"details,omitempty"`
}

func SendErrorResponse(w http.ResponseWriter, r *http.Request, status int, message string) {
	err := jsn.WriteJSON(w, status, ErrorResponse{Error: message}, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func SendErrorResponseWithDetails(w http.ResponseWriter, r *http.Request, status int, message string, details map[string]interface{}) {
	err := jsn.WriteJSON(w, status, ErrorResponseWithDetails{Error: message, Details: details}, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func ServerErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
	message := "the server encountered a problem, please try again later"
	SendErrorResponse(w, r, http.StatusInternalServerError, message)
}

func NotFoundResponse(w http.ResponseWriter, r *http.Request) {
	message := "the requested resource could not be found"
	SendErrorResponse(w, r, http.StatusNotFound, message)
}

func MethodNotAllowedResponse(w http.ResponseWriter, r *http.Request) {
	message := fmt.Sprintf("the %s method is not supported for this resource", r.Method)
	SendErrorResponse(w, r, http.StatusMethodNotAllowed, message)
}

func BadRequestResponse(w http.ResponseWriter, r *http.Request, err error) {
	SendErrorResponse(w, r, http.StatusBadRequest, err.Error())
}
