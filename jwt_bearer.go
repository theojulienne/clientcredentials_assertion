package clientcredentials_assertion

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const ClientAssertionTypeJwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func JwtBearerAssertionFromPrivateKey(clientId string, privateKey *rsa.PrivateKey, opts ...JwtBearerAssertionOption) BearerAssertionFunc {
	return func(assertionConfig *Config) (clientAssertionType string, clientAssertion string, err error) {
		clientAssertionType = ClientAssertionTypeJwtBearer
		claimsToValidate := jwt.RegisteredClaims{
			// REQUIRED. Issuer. This MUST contain the client_id of the OAuth Client.
			Issuer: clientId,
			// REQUIRED. Subject. This MUST contain the client_id of the OAuth Client.
			Subject: clientId,
			// REQUIRED. Audience. The aud (audience) Claim. Value that identifies the
			// Authorization Server as an intended audience. The Authorization Server MUST
			// verify that it is an intended audience for the token. The Audience SHOULD
			// be the URL of the Authorization Server's Token Endpoint.
			Audience: []string{assertionConfig.TokenURL},
			// REQUIRED. JWT ID. A unique identifier for the token, which can be used to
			// prevent reuse of the token. These tokens MUST only be used once, unless
			// conditions for reuse were negotiated between the parties; any such negotiation
			// is beyond the scope of this specification.
			ID: uuid.New().String(),
			// REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
			// OPTIONAL. Time at which the JWT was issued.
			IssuedAt: jwt.NewNumericDate(time.Now()),
			// The JWT MAY contain an "nbf" (not before) claim that identifies
			// the time before which the token MUST NOT be accepted for
			// processing.
			NotBefore: jwt.NewNumericDate(time.Now()),
		}
		for _, opt := range opts {
			opt(&claimsToValidate)
		}
		clientAssertion, err = jwt.NewWithClaims(jwt.SigningMethodRS256, claimsToValidate).SignedString(privateKey)
		return
	}
}

type JwtBearerAssertionOption func(*jwt.RegisteredClaims)

func WithOverriddenAudience(audience ...string) JwtBearerAssertionOption {
	return func(claims *jwt.RegisteredClaims) {
		claims.Audience = audience
	}
}
