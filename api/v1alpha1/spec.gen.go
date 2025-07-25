// Package v1alpha1 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.3.0 DO NOT EDIT.
package v1alpha1

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
