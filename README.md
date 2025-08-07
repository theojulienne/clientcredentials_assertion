# clientcredentials_assertion

A Go package that extends the standard Go OAuth2 client credentials flow to support client assertions (JWT Bearer tokens) instead of client secrets.

## Overview

This package provides a drop-in replacement for `golang.org/x/oauth2/clientcredentials.Config` that supports OAuth2 client assertions as defined in [RFC 7521](https://tools.ietf.org/html/rfc7521). Instead of using a client secret, clients can authenticate using a JWT Bearer assertion.

## Features

- **JWT Bearer Assertions**: Support for RFC 7521 JWT Bearer client assertions
- **Drop-in Replacement**: Compatible with standard OAuth2 client credentials flow
- **Automatic Token Refresh**: Handles token expiration and refresh automatically
- **HTTP Client Integration**: Provides pre-configured HTTP clients with automatic token injection

## Installation

```bash
go get github.com/theojulienne/clientcredentials_assertion
```

## Usage

### Basic Example

```go
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/url"

	"github.com/theojulienne/clientcredentials_assertion"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/oauth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	// Parse your RSA private key
	privateKeyPEM := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`
	
	block, _ := pem.Decode([]byte(privateKeyPEM))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	// Create assertion configuration
	assertionConfig := &clientcredentials_assertion.Config{
		Config: clientcredentials.Config{
			ClientID: "your-client-id",
			TokenURL: "https://auth.example.com/oauth/token",
			EndpointParams: url.Values{
				"resource": {"https://api.example.com/"},
			},
		},
		GetClientAssertion: clientcredentials_assertion.JwtBearerAssertionFromPrivateKey(
			"your-client-id",
			privateKey,
		),
	}

	// Create token source
	ctx := context.Background()
	tokenSource := oauth.TokenSource{
		TokenSource: assertionConfig.TokenSource(ctx),
	}

	// Use with gRPC credentials
	conn, err := grpc.Dial(
		"api.example.com:443",
		grpc.WithTransportCredentials(credentials.NewTLS(nil)),
		grpc.WithPerRPCCredentials(tokenSource),
	)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Or use with HTTP client
	httpClient := assertionConfig.Client(ctx)
	// Use httpClient for API calls...
}
```

### Configuration Options

The `Config` struct embeds/extends the standard `clientcredentials.Config`, you will typically need to provide:

- **GetClientAssertion**: A function (specific to the assertion package) that returns the assertion.
  - `JwtBearerAssertionFromPrivateKey` returns a getter function that generates assertions based on the client ID and RSA private key (RS256) provided.
- **ClientID**: Your OAuth2 client identifier
- **TokenURL**: The OAuth2 token endpoint URL
- **EndpointParams**: Additional parameters to include in token requests (e.g., `resource`)

### JWT Bearer Assertion Helper

The package provides a helper function for creating JWT Bearer assertions using RSA private keys (RS256):

```go
GetClientAssertion: clientcredentials_assertion.JwtBearerAssertionFromPrivateKey(
    clientID,
    privateKey,
)
```

This creates a JWT with the following claims, signed with RS256 using the private key provided:
- `iss` (issuer): The client ID
- `sub` (subject): The client ID  
- `aud` (audience): The token URL
- `jti` (JWT ID): A unique identifier
- `exp` (expiration): 10 minutes from now
- `iat` (issued at): Current time
- `nbf` (not before): Current time

## Testing

Run the test suite:

```bash
go test ./...
```

## License

This package is released under the MIT License.
