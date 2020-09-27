package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/JackOfMostTrades/spiffe-user-demo/common"
	"github.com/coreos/go-oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

func main() {
	err := doMain()
	if err != nil {
		panic(err)
	}
}

func createAuthToken(macKey []byte, sub string) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: macKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}

	iat := jwt.NumericDate(time.Now().Unix())
	exp := jwt.NumericDate(time.Now().Add(14 * 24 * time.Hour).Unix())

	raw, err := jwt.Signed(sig).Claims(&jwt.Claims{
		Subject:  sub,
		IssuedAt: &iat,
		Expiry:   &exp,
	}).CompactSerialize()
	if err != nil {
		return "", err
	}
	return raw, nil
}

func validateAuthToken(macKey []byte, token string) (*jwt.Claims, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, err
	}

	out := &jwt.Claims{}
	if err := tok.Claims(macKey, &out); err != nil {
		return nil, err
	}
	if err := out.Validate(jwt.Expected{Time: time.Now()}); err != nil {
		return nil, err
	}

	return out, nil
}

func doMain() error {
	var err error
	if _, err := os.Stat(".env"); err == nil {
		err := godotenv.Load(".env")
		if err != nil {
			return fmt.Errorf("error loading .env file: %v", err)
		}
	}

	flagSet := flag.NewFlagSet("spiffe-user-demo-server", flag.ContinueOnError)
	var port int
	flagSet.IntVar(&port, "port", 8080, "Port to listen on")

	err = flagSet.Parse(os.Args[1:])
	if err != nil {
		return fmt.Errorf("unable to parse args: %v", err)
	}

	var macKey []byte
	if macKeyB64 := os.Getenv("AUTH_TOKEN_MAC_KEY"); macKeyB64 != "" {
		macKey, err = base64.StdEncoding.DecodeString(macKeyB64)
		if err != nil {
			return fmt.Errorf("failed to decode auth token MAC key: %v", err)
		}
	} else {
		log.Println("Generating a random auth token MAC key...")
		macKey = make([]byte, 32)
		_, err = rand.Read(macKey)
		if err != nil {
			return fmt.Errorf("unable to generate macKey: %v", err)
		}
	}

	var jwtKey crypto.PrivateKey
	if jwtKeyB64 := os.Getenv("JWT_SIGNING_KEY"); jwtKeyB64 != "" {
		jwtKeyBytes, err := base64.StdEncoding.DecodeString(jwtKeyB64)
		if err != nil {
			return fmt.Errorf("failed to base64 decode JWT signing key: %v", err)
		}
		jwtKey, err = x509.ParsePKCS8PrivateKey(jwtKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse JWT signing key: %v", err)
		}
	} else {
		log.Println("Generating a random JWT signing key...")
		jwtKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("unable to generate JWT key: %v", err)
		}
	}
	jwk := jose.JSONWebKey{
		Key:   jwtKey,
		KeyID: "1",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk.Public()}}

	var caKey crypto.PrivateKey
	var caCert *x509.Certificate
	if caKeyB64, caCertB64 := os.Getenv("CA_PRIVATE_KEY"), os.Getenv("CA_CERTIFICATE"); caKeyB64 != "" && caCertB64 != "" {
		caKeyBytes, err := base64.StdEncoding.DecodeString(caKeyB64)
		if err != nil {
			return fmt.Errorf("failed to base64 decode CA private key: %v", err)
		}
		caKey, err = x509.ParsePKCS8PrivateKey(caKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA private key: %v", err)
		}
		caCertBytes, err := base64.StdEncoding.DecodeString(caCertB64)
		if err != nil {
			return fmt.Errorf("failed to base64 decode CA certificate: %v", err)
		}
		caCert, err = x509.ParseCertificate(caCertBytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %v", err)
		}
	} else {
		log.Println("Generating a random X.509 key/certificate")
		caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("unable to generate CA key: %v", err)
		}
		caKey = caPrivateKey

		template := &x509.Certificate{
			SerialNumber: randomSerial(),
			Subject: pkix.Name{
				Organization: []string{"Acme Co"},
				CommonName:   "User SPIFFE Demo Root CA",
			},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(365 * 30 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		caCertBytes, err := x509.CreateCertificate(rand.Reader, template, template, caPrivateKey.Public(), caPrivateKey)
		if err != nil {
			return fmt.Errorf("unable to generate self-signed root CA: %v", err)
		}
		caCert, err = x509.ParseCertificate(caCertBytes)
		if err != nil {
			return fmt.Errorf("unable to parse generated root CA: %v", err)
		}
	}

	println("CA Certificate:")
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	println("JWKS:")
	json.NewEncoder(os.Stdout).Encode(jwks)

	oidcProviderUrl := os.Getenv("OIDC_PROVIDER_URL")
	if oidcProviderUrl == "" {
		oidcProviderUrl = "https://accounts.google.com"
	}
	log.Printf("Using OIDC provider URL: %s\n", oidcProviderUrl)

	oidcClientId := os.Getenv("OIDC_CLIENT_ID")
	oidcClientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	if oidcClientId == "" || oidcClientSecret == "" {
		log.Fatal("OIDC_CLIENT_ID and OIDC_CLIENT_SECRET environment parameters are required.")
	}
	trustDomain := os.Getenv("TRUST_DOMAIN")
	if trustDomain == "" {
		trustDomain = "spiffe-user-demo.herokuapp.com"
	}

	oidcProvider, err := oidc.NewProvider(context.Background(), oidcProviderUrl)
	if err != nil {
		return err
	}
	serviceUrl := os.Getenv("SERVICE_URL")
	if serviceUrl == "" {
		serviceUrl = "http://127.0.0.1:8080"
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     oidcClientId,
		ClientSecret: oidcClientSecret,
		RedirectURL:  fmt.Sprintf("%s/login", serviceUrl),

		// Discovery returns the OAuth2 endpoints.
		Endpoint: oidcProvider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "email"},
	}
	oidcVerifier := oidcProvider.Verifier(&oidc.Config{
		ClientID: oidcClientId,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(writer http.ResponseWriter, request *http.Request) {
		json.NewEncoder(writer).Encode(&common.GetJwksResponse{
			TrustDomain: trustDomain,
			Jwks:        &jwks,
		})
	})
	mux.HandleFunc("/jwt", func(writer http.ResponseWriter, request *http.Request) {
		req := new(common.GetUserJwtRequest)
		err := json.NewDecoder(request.Body).Decode(req)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		claims, err := validateAuthToken(macKey, req.AuthToken)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		raw, err := jwt.Signed(sig).Claims(&jwt.Claims{
			Subject:  fmt.Sprintf("spiffe://%s/%s", trustDomain, url.PathEscape(claims.Subject)),
			Audience: req.Audience,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(14 * 24 * time.Hour)),
		}).CompactSerialize()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(writer).Encode(&common.GetUserJwtResponse{UserJwt: raw})
	})
	mux.HandleFunc("/x509", func(writer http.ResponseWriter, request *http.Request) {
		req := new(common.GetUserX509Request)
		err := json.NewDecoder(request.Body).Decode(req)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		pubKey, err := x509.ParsePKIXPublicKey(req.PublicKey)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		claims, err := validateAuthToken(macKey, req.AuthToken)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		spid := &url.URL{
			Scheme: "spiffe",
			Host:   trustDomain,
			Path:   claims.Subject,
		}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		template := &x509.Certificate{
			SerialNumber:          randomSerial(),
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(48 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth | x509.ExtKeyUsageServerAuth},
			URIs:                  []*url.URL{spid},
			BasicConstraintsValid: true,
			IsCA:                  false,
		}
		cert, err := x509.CreateCertificate(rand.Reader, template, caCert, pubKey, caKey)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(writer).Encode(&common.GetUserX509Response{CertificateChain: [][]byte{cert, caCert.Raw}})
	})
	mux.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) {
		var state struct {
			Nonce        string `json:"nonce"`
			CallbackPort int    `json:"callback"`
		}

		code := request.URL.Query().Get("code")
		if code == "" {
			callbackPort, err := strconv.Atoi(request.URL.Query().Get("callback"))
			if err != nil {
				http.Error(writer, "Unable to parse callback port", http.StatusBadRequest)
				return
			}

			state.Nonce = randomNonceString()
			state.CallbackPort = callbackPort
			stateVal, err := json.Marshal(&state)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
			http.SetCookie(writer, &http.Cookie{
				HttpOnly: true,
				Name:     "oidc_state",
				Value:    base64.RawURLEncoding.EncodeToString(stateVal),
			})
			http.Redirect(writer, request, oauth2Config.AuthCodeURL(state.Nonce), http.StatusFound)
			return
		}

		stateCookie, err := request.Cookie("oidc_state")
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		stateCookeBytes, err := base64.RawURLEncoding.DecodeString(stateCookie.Value)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		err = json.Unmarshal(stateCookeBytes, &state)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		if state.Nonce == "" || state.Nonce != request.URL.Query().Get("state") {
			http.Error(writer, "Invalid OIDC state", http.StatusBadRequest)
			return
		}

		oauth2Token, err := oauth2Config.Exchange(request.Context(), code)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(writer, "Unable to get ID token from OIDC exchange", http.StatusInternalServerError)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := oidcVerifier.Verify(request.Context(), rawIDToken)
		if err != nil {
			http.Error(writer, "Unable to verify ID token from OIDC exchange", http.StatusInternalServerError)
			return
		}
		var claims struct {
			Email string `json:"email"`
		}
		err = idToken.Claims(&claims)
		if err != nil || claims.Email == "" {
			http.Error(writer, "Unable to get email from ID token", http.StatusInternalServerError)
			return
		}

		authToken, err := createAuthToken(macKey, claims.Email)
		if err != nil {
			http.Error(writer, "Unable to create auth token: "+err.Error(), http.StatusInternalServerError)
		}

		writer.Write([]byte(fmt.Sprintf(`<html><body><div id="status">Loading...</div><script type="text/javascript">
function done() {
  document.getElementById('status').innerHTML = 'Login complete. You can close this tab.';
}

fetch("http://127.0.0.1:%d", {
  "method": "POST",
  "headers": {"Content-Type": "application/json"},
  "body": JSON.stringify({"authToken": "%s"})
}).then(done);
</script></body></html>`, state.CallbackPort, authToken)))
	})

	http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), mux)
	return nil
}

func randomNonceString() string {
	// 32 bytes rounded up to a multiple of 3
	b := make([]byte, 33)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func randomSerial() *big.Int {
	// We want 136 bits of random number, plus an 8-bit prefix (which we always set to 0x01 here).
	serial := make([]byte, 17)
	_, err := rand.Read(serial)
	if err != nil {
		panic(err)
	}
	serial = append([]byte{0x01}, serial...)
	return big.NewInt(0).SetBytes(serial)
}
