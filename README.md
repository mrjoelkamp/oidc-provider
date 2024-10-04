# oidc-provider

This is minimal OpenID Connect authorization server, using the OAuth 2.0 + PKCE flow that issues an ID Token.

The provider does not require a `client_id` or user login.

> :memo: **note:** the server is backwards compatible with OAuth 2.0 without PKCE if the PKCE parameters `code_challenge` and `code_challenge_mode` are omitted from the authentication request

## Configuration

`host` and `port` can be configured my editing the configuration parameters in [main.go](./main.go)

## Building and Running

### Docker

To build the oidc-provider docker image:
```console
make docker-build
```

To run the oidc-provider docker image:
```console
make docker-run
```


Alternatively, you can build and run the docker image without using the Makefile:
  ```console
  docker build -t oidc-provider .
  ```
  ```console
  docker run --network=host -p 5001:5001 oidc-provider
  ```

### Local Go

To build the oidc-provider app using Go run `make build`

To run the oidc-provider app using Go run `make run`

### Generating keys

There is a pre-generated example key in `./keys` that can be used to build and run the OP. 

To generate new keys simply run `make keys`.

## Tests

Tests can be run for the major components by running `make test`.

Alternatively, you can run the tests via Go by running `go test ./...`

## How to read this code

The authentication endpoints are implemented in `discovery.go`, `jwks.go`, `authorization.go` and `token.go`. These contain all of the handlers and logic needed for the OAuth 2.0 Authorization Code w/ PKCE flow. They each have associated tests in their respective `*_test.go` files.

The application entry point is `main.go` which contains a hardcoded configuration that initializes and starts the server.

The Crypto operations are implemented in `crypto.go`.

All storage is in-memory and implemented in `storage.go`.

## Improvements

There are many improvements that can be made but have been deferred due to time constraints. Some improvements are noted with `TODO:` comments throughout the code.
