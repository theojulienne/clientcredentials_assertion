package clientcredentials_assertion

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/clientcredentials"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey
}

func TestJwtBearerAssertionFromPrivateKey(t *testing.T) {
	privateKey := generateTestKey(t)
	clientID := "test-client-id"
	tokenURL := "https://auth.example.com/token"

	// Create the assertion function
	assertionFunc := JwtBearerAssertionFromPrivateKey(clientID, privateKey)

	// Create test config
	config := &Config{
		Config: clientcredentials.Config{
			ClientID: clientID,
			TokenURL: tokenURL,
		},
	}

	// Get the assertion
	assertionType, assertion, err := assertionFunc(config)
	require.NoError(t, err)
	assert.Equal(t, ClientAssertionTypeJwtBearer, assertionType)

	// Parse and verify the JWT
	var registeredClaims jwt.RegisteredClaims
	token, err := jwt.ParseWithClaims(assertion, &registeredClaims, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)

	assert.Equal(t, clientID, registeredClaims.Issuer)
	assert.Equal(t, clientID, registeredClaims.Subject)
	assert.Contains(t, registeredClaims.Audience, tokenURL)
	assert.NotEmpty(t, registeredClaims.ID)
	assert.True(t, registeredClaims.ExpiresAt.Time.After(time.Now()))
	assert.True(t, registeredClaims.IssuedAt.Time.Before(time.Now().Add(time.Second)))
	assert.True(t, registeredClaims.NotBefore.Time.Before(time.Now().Add(time.Second)))
}

func TestJwtBearerAssertion_Integration(t *testing.T) {
	privateKey := generateTestKey(t)
	clientID := "test-client-id"

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse form data
		err := r.ParseForm()
		require.NoError(t, err)

		// Verify basic request parameters
		assert.Equal(t, clientID, r.Form.Get("client_id"))
		assert.Equal(t, ClientAssertionTypeJwtBearer, r.Form.Get("client_assertion_type"))
		assertion := r.Form.Get("client_assertion")
		assert.NotEmpty(t, assertion)

		// Parse and verify the JWT
		var registeredClaims jwt.RegisteredClaims
		token, err := jwt.ParseWithClaims(assertion, &registeredClaims, func(token *jwt.Token) (interface{}, error) {
			return &privateKey.PublicKey, nil
		})
		require.NoError(t, err)
		assert.True(t, token.Valid)

		// Verify claims
		assert.Equal(t, clientID, registeredClaims.Issuer)
		assert.Equal(t, clientID, registeredClaims.Subject)
		assert.Contains(t, registeredClaims.Audience, "http://"+r.Host+"/token")
		assert.NotEmpty(t, registeredClaims.ID)
		assert.True(t, registeredClaims.ExpiresAt.Time.After(time.Now()))
		assert.True(t, registeredClaims.IssuedAt.Time.Before(time.Now().Add(time.Second)))
		assert.True(t, registeredClaims.NotBefore.Time.Before(time.Now().Add(time.Second)))

		// Send success response
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	// Create config with JWT Bearer assertion
	config := &Config{
		Config: clientcredentials.Config{
			ClientID: clientID,
			TokenURL: server.URL + "/token",
		},
		GetClientAssertion: JwtBearerAssertionFromPrivateKey(clientID, privateKey),
	}

	// Get token
	token, err := config.Token(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "test-token", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
}
