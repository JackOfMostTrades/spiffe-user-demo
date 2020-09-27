package common

import "gopkg.in/square/go-jose.v2"

type GetUserX509Request struct {
	AuthToken string `json:"authToken"`
	PublicKey []byte `json:"publicKey"`
}

type GetUserX509Response struct {
	CertificateChain [][]byte `json:"certificateChain"`
}

type GetUserJwtRequest struct {
	AuthToken string   `json:"authToken"`
	Audience  []string `json:"audience"`
}

type GetUserJwtResponse struct {
	UserJwt string `json:"userJwt"`
}

type GetJwksResponse struct {
	TrustDomain string              `json:"trustDomain"`
	Jwks        *jose.JSONWebKeySet `json:"jwks"`
}
