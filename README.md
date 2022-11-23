spiffe-user-demo
================

This is a proof of concept project that runs a SPIFFE Workload API service meant to provide user-based SVIDs on developer endpoints, bootstrapped from an SSO login. This demo in particular integrates with OIDC providers to enable user login, but generalizes to any web application SSO.

Demo
----

I'm hosting a demo server, configured with Google's OIDC provider. You can run the `spiffe-user-demo` to start up a workload API service on your endpoint. You can run a workload API instance on your workstation by using the binary from this repo without any arguments: `./spiffe-user-demo`.

Using [spiffe-watcher](https://github.com/spiffe/go-spiffe/tree/master/v2/examples/spiffe-watcher), this is an example of the X.509-SVIDs that get retrieved from the endpoint.

```bash
$ spiffe-watcher 
2020/09/27 15:28:17 jwt bundle updated "spiffe-user-demo.fly.dev": {"keys":[{"kty":"EC","kid":"1","crv":"P-256","x":"i5bOW6bqc_D-KV4-O9TIvt_5VJvPpqnolQCgcwrREz8","y":"-6SOM0wF813sH_fMW-8iQGdNNIxryTjeszYBDGu78c4"}]}
2020/09/27 15:28:17 SVID updated for "spiffe://spiffe-user-demo.fly.dev/ianhaken@gmail.com": 
-----BEGIN CERTIFICATE-----
MIIBszCCAVqgAwIBAgISAbDYa/82lma7zLepQuml5TzVMAoGCCqGSM49BAMCMDUx
EDAOBgNVBAoTB0FjbWUgQ28xITAfBgNVBAMTGFVzZXIgU1BJRkZFIERlbW8gUm9v
dCBDQTAeFw0yMDA5MjcyMTI2MzdaFw0yMDA5MjkyMjI2MzdaMAAwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAASMSYZNs764pzyvILCmAYUjL6iQxpE5CFHULAppQmtr
rc1ZcgJZSyIvQC/HtgG+i5DcXrFvCo9oAsU+XlZXe/Iro38wfTAOBgNVHQ8BAf8E
BAMCA7gwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDAYDVR0TAQH/BAIwADBIBgNVHREB
Af8EPjA8hjpzcGlmZmU6Ly9zcGlmZmUtdXNlci1kZW1vLmhlcm9rdWFwcC5jb20v
aWFuaGFrZW5AZ21haWwuY29tMAoGCCqGSM49BAMCA0cAMEQCIA4LF4uyNZ02m6My
4SUNGQUPNWIkQFlRZ3pit/Q1xmvYAiB5YpRyVYNqI/cgg4OK7G9vaDaQD3xYkffi
/cjeFVo4Nw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgISAVrD8ihVt1r1LLS26md4IAv0MAoGCCqGSM49BAMCMDUx
EDAOBgNVBAoTB0FjbWUgQ28xITAfBgNVBAMTGFVzZXIgU1BJRkZFIERlbW8gUm9v
dCBDQTAgFw0yMDA5MjcyMDIxMDhaGA8yMDUwMDkyMDIxMjEwOFowNTEQMA4GA1UE
ChMHQWNtZSBDbzEhMB8GA1UEAxMYVXNlciBTUElGRkUgRGVtbyBSb290IENBMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmurK9Thry/eNTkJt3Iu0ZxT0VL4qAs2X
ABYyAzBHwtDalNcgUyvS4rZ5UT4vNSeg+aBlFpfDGCFjoEfVMdqMJqMjMCEwDgYD
VR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIg
CH4KWHE/V7QQUOqsxtN1W778Y7ZkzFRPl58zJvDhkFUCIQDlN7dNU2Q+WwhNWj3h
3/PtlY23m0WhNpyEIJrP8QCatg==
-----END CERTIFICATE-----
```

Server Configuration
--------------------

The server is configured using environment variables and supports loading a `.env` file with environment variables; see [godotenv](https://github.com/joho/godotenv).

This is an example `.env` with comments:

```bash
# This should be a base64-encoded 32 byte random value. It is used to MAC the authentication tokens used between the service and clients.
AUTH_TOKEN_MAC_KEY=
# Base64 PKCS8 encoded private key used to sign the JWT-SVIDs
JWT_SIGNING_KEY=
# Base64 DER encoded X.509 CA certificate used as the root CA for X509-SVIDs
CA_CERTIFICATE=
# Base64 PKCS8 encoded private key of the CA certificate above
CA_PRIVATE_KEY=
# The URL of your service. This is used to build the redirect URL with the OIDC service provider
SERVICE_URL=https://spiffe-user-demo.fly.dev
# The OIDC service provider to use.
OIDC_PROVIDER_URL=https://accounts.google.com
# The OIDC client id and secret
OIDC_CLIENT_ID=
OIDC_CLIENT_SECRET=
# The trust domain that will be used to build the SPIFFE IDs returned by the server
TRUST_DOMAIN=spiffe-user-demo.fly.dev
```
