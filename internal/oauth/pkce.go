package oauth

import "errors"

func ValidatePKCE(challenge, method string) error {
	if challenge == "" {
		return errors.New("missing code_challenge")
	}
	if method != "S256" {
		return errors.New("only S256 supported")
	}
	return nil
}
