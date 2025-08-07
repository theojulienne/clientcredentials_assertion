package clientcredentials_assertion

import (
	"context"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type BearerAssertionFunc func(assertionConfig *Config) (clientAssertionType string, clientAssertion string, err error)

// Config defines the additional configuration for the client credentials assertion.
// The ClientCredentialsConfig embedded config must also be filled in, except for the ClientSecret field.
type Config struct {
	clientcredentials.Config

	// GetClientAssertion is a function that returns the client assertion to use for the token request.
	// It is called when the TokenSource is created, and the token is refreshed.
	// The function must return the value of client_assertion_type and client_assertion.
	GetClientAssertion BearerAssertionFunc
}

// See clientcredentials.Config.Token
func (c *Config) Token(ctx context.Context) (*oauth2.Token, error) {
	return c.TokenSource(ctx).Token()
}

// See clientcredentials.Config.Client
func (c *Config) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, c.TokenSource(ctx))
}

// See clientcredentials.Config.TokenSource
func (c *Config) TokenSource(ctx context.Context) oauth2.TokenSource {
	source := &tokenSource{
		ctx:  ctx,
		conf: c,
	}
	return oauth2.ReuseTokenSource(nil, source)
}

type tokenSource struct {
	ctx  context.Context
	conf *Config
}

// injects updated information into the underlying client credentials config and uses it to issue the token
func (c *tokenSource) Token() (*oauth2.Token, error) {
	clientAssertionType, clientAssertion, err := c.conf.GetClientAssertion(c.conf)
	if err != nil {
		return nil, err
	}

	cc := c.conf.Config
	cc.ClientSecret = ""                    // MUST be empty because we're using an assertion
	cc.AuthStyle = oauth2.AuthStyleInParams // MUST be in params because we're using an assertion
	if cc.EndpointParams == nil {
		cc.EndpointParams = url.Values{}
	}
	cc.EndpointParams.Set("client_assertion_type", clientAssertionType)
	cc.EndpointParams.Set("client_assertion", clientAssertion)

	return cc.Token(c.ctx)
}
