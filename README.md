# Google Chat ID Token Validator

Google Chat includes a bearer token in the Authorization header of every HTTPS Request to a app. This library is used to verify that the request is actually coming from Google.

## Usage

### Get the go-lib module

Note that you need to include the **v** in the version tag.

```
$ go get github.com/dennbagas/gchat-idtoken-validator@v0.1.0
```

## Testing

```
$ go test
```
