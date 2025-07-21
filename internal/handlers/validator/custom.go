package validator

import (
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

var (
	sshRegex = []*regexp.Regexp{
		regexp.MustCompile(`^ssh-rsa AAAAB3NzaC1yc2[0-9A-Za-z+/]+[=]{0,3}(\s.*)?$`),
		regexp.MustCompile(`^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5[0-9A-Za-z+/]+[=]{0,3}(\s.*)?$`),
		regexp.MustCompile(`^ssh-dss AAAAB3NzaC1kc3[0-9A-Za-z+/]+[=]{0,3}(\s.*)?$`),
		regexp.MustCompile(`^ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNT[0-9A-Za-z+/]+[=]{0,3}(\\s.*)?$`),
	}

	sourceNameValidRegex = regexp.MustCompile("^[a-zA-Z0-9+-_.]+$")
	labelRegex           = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)
)

// nameValidator checks if the field is a string that matches the allowed source name pattern.
// Returns false if the field is not a string or does not conform to the pattern.
func nameValidator(fl validator.FieldLevel) bool {
	val, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}

	return sourceNameValidRegex.MatchString(val)
}

func sshKeyValidator(fl validator.FieldLevel) bool {
	val, ok := fl.Field().Addr().Interface().(*string)
	if !ok {
		return false
	}

	if val == nil {
		return true
	}

	for _, r := range sshRegex {
		if r.MatchString(*val) {
			return true
		}
	}

	return false
}

func certificateValidator(fl validator.FieldLevel) bool {
	val, ok := fl.Field().Addr().Interface().(*string)
	if !ok {
		return false
	}

	if val == nil {
		return true
	}

	block, _ := pem.Decode([]byte(*val))
	if block == nil {
		return false
	}

	_, err := x509.ParseCertificate(block.Bytes)
	return err == nil
}

func agentStatusValidator(fl validator.FieldLevel) bool {
	val, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}
	switch val {
	case "not-connected":
		fallthrough
	case "waiting-for-credentials":
		fallthrough
	case "error":
		fallthrough
	case "gathering-initial-inventory":
		fallthrough
	case "up-to-date":
		fallthrough
	case "source-gone":
		return true
	default:
		return false
	}
}

// uuidValidator checks whether the field is a non-zero uuid.UUID value.
// Returns false if the field is not of type uuid.UUID or is the zero UUID.
func uuidValidator(fl validator.FieldLevel) bool {
	val, ok := fl.Field().Interface().(uuid.UUID)
	if !ok {
		return false
	}
	return val != uuid.UUID{}
}

// labelValidator checks if a string field is a valid label, ensuring it is non-empty, starts and ends with an alphanumeric character, and contains only alphanumeric characters, dots, underscores, or hyphens. Returns false if the field is not a string.
func labelValidator(fl validator.FieldLevel) bool {
	val, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}

	// Label key/value should not be empty
	// Allow alphanumeric characters, hyphens, underscores, and dots
	// Must start and end with alphanumeric character
	return labelRegex.MatchString(val)
}

// startsWithValidator checks if a pointer to a string is nil or if its value starts with the specified prefix parameter.
// Returns false if the field is not a pointer to a string.
func startsWithValidator(fl validator.FieldLevel) bool {
	val, ok := fl.Field().Addr().Interface().(*string)
	if !ok {
		return false
	}

	if val == nil {
		return true
	}

	param := fl.Param()
	return strings.HasPrefix(*val, param)
}

func startsNotWithValidator(fl validator.FieldLevel) bool {
	val, ok := fl.Field().Addr().Interface().(*string)
	if !ok {
		return false
	}

	if val == nil {
		return true
	}

	param := fl.Param()
	return !strings.HasPrefix(*val, param)
}
