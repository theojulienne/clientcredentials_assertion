package clientcredentials_assertion

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func TestConfig_Token_Success(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request parameters
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "test-client-id", r.Form.Get("client_id"))
		assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))
		assert.Equal(t, "test-assertion", r.Form.Get("client_assertion"))
		assert.Equal(t, "test-scope", r.Form.Get("scope"))
		assert.Empty(t, r.Form.Get("client_secret"), "client_secret should be empty when using assertions")

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"test-access-token","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	// Create config
	config := &Config{
		Config: clientcredentials.Config{
			ClientID:       "test-client-id",
			TokenURL:       server.URL + "/token",
			Scopes:         []string{"test-scope"},
			EndpointParams: url.Values{},
		},
		GetClientAssertion: func(config *Config) (string, string, error) {
			return "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "test-assertion", nil
		},
	}

	// Get token
	token, err := config.Token(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "test-access-token", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
}

func TestConfig_Token_AssertionError(t *testing.T) {
	// Create config with assertion function that returns error
	config := &Config{
		Config: clientcredentials.Config{
			ClientID: "test-client-id",
			TokenURL: "http://example.com/token",
		},
		GetClientAssertion: func(config *Config) (string, string, error) {
			return "", "", assert.AnError
		},
	}

	// Get token should fail
	token, err := config.Token(context.Background())
	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestConfig_Client(t *testing.T) {
	config := &Config{
		Config: clientcredentials.Config{
			ClientID: "test-client-id",
			TokenURL: "http://example.com/token",
		},
		GetClientAssertion: func(config *Config) (string, string, error) {
			return "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "test-assertion", nil
		},
	}

	client := config.Client(context.Background())
	assert.NotNil(t, client)
	assert.IsType(t, &http.Client{}, client)
}

func TestConfig_TokenSource(t *testing.T) {
	config := &Config{
		Config: clientcredentials.Config{
			ClientID: "test-client-id",
			TokenURL: "http://example.com/token",
		},
		GetClientAssertion: func(config *Config) (string, string, error) {
			return "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "test-assertion", nil
		},
	}

	tokenSource := config.TokenSource(context.Background())
	assert.NotNil(t, tokenSource)
	assert.Implements(t, (*oauth2.TokenSource)(nil), tokenSource)
}

func TestTokenSource_Token_Success(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request parameters
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "test-client-id", r.Form.Get("client_id"))
		assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))
		assert.Equal(t, "test-assertion", r.Form.Get("client_assertion"))
		assert.Equal(t, "test-scope", r.Form.Get("scope"))
		assert.Empty(t, r.Form.Get("client_secret"), "client_secret should be empty when using assertions")

		// Verify request method and headers
		assert.Equal(t, "POST", r.Method)
		assert.True(t, strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"))

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"test-access-token","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	// Create token source
	ts := &tokenSource{
		ctx: context.Background(),
		conf: &Config{
			Config: clientcredentials.Config{
				ClientID:       "test-client-id",
				TokenURL:       server.URL + "/token",
				Scopes:         []string{"test-scope"},
				EndpointParams: url.Values{},
			},
			GetClientAssertion: func(config *Config) (string, string, error) {
				return "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "test-assertion", nil
			},
		},
	}

	// Get token
	token, err := ts.Token()
	require.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "test-access-token", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
}

func TestTokenSource_Token_AssertionError(t *testing.T) {
	// Create token source with assertion function that returns error
	ts := &tokenSource{
		ctx: context.Background(),
		conf: &Config{
			Config: clientcredentials.Config{
				ClientID: "test-client-id",
				TokenURL: "http://example.com/token",
			},
			GetClientAssertion: func(config *Config) (string, string, error) {
				return "", "", assert.AnError
			},
		},
	}

	// Get token should fail
	token, err := ts.Token()
	assert.Error(t, err)
	assert.Nil(t, token)
}
