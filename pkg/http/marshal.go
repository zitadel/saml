package http

import (
	"encoding/json"
	"net/http"
	"reflect"
)

func MarshalJSON(w http.ResponseWriter, i interface{}) {
	MarshalJSONWithStatus(w, i, http.StatusOK)
}

func MarshalJSONWithStatus(w http.ResponseWriter, i interface{}, status int) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	if i == nil || (reflect.ValueOf(i).Kind() == reflect.Ptr && reflect.ValueOf(i).IsNil()) {
		return
	}
	err := json.NewEncoder(w).Encode(i)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
