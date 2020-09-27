package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/JackOfMostTrades/spiffe-user-demo/common"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"
)

type MockClient struct {
	UserClient
	counter int64
}

func (c *MockClient) GetUserX509(req *common.GetUserX509Request) (*common.GetUserX509Response, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	svid, err := url.Parse("spiffe://foo.example.com/web/blog")
	if err != nil {
		return nil, err
	}

	serial := big.NewInt(c.counter)
	c.counter += 1

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "foo"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"foo.example.com"},
		URIs:                  []*url.URL{svid},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return nil, err
	}

	return &common.GetUserX509Response{
		CertificateChain: [][]byte{cert},
	}, nil
}

func runInTestEnv(t *testing.T, testFunc func(client workload.SpiffeWorkloadAPIClient)) {
	tmpPath, err := ioutil.TempFile(os.TempDir(), "agent-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpPath.Name())
	tmpPath.Close()

	mockClient := new(MockClient)
	logger := logrus.New()
	logger.Level = logrus.PanicLevel

	server, err := StartWorkloadServiceServer(&WorkloadServiceServerOptions{
		SocketPath:       tmpPath.Name(),
		Logger:           logger,
		Client:           mockClient,
		RefreshFrequency: 1 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()

	conn, err := grpc.Dial("unix://"+tmpPath.Name(), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := workload.NewSpiffeWorkloadAPIClient(conn)
	testFunc(client)
}

func TestFetchX509SVID(t *testing.T) {
	runInTestEnv(t, func(client workload.SpiffeWorkloadAPIClient) {
		header := metadata.New(map[string]string{"workload.spiffe.io": "true"})
		ctx, cancel := context.WithCancel(metadata.NewOutgoingContext(context.Background(), header))
		stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		cancel()

		if len(resp.Svids) != 1 {
			t.Errorf("Expected exactly 1 SVID in response: %d", len(resp.Svids))
		}
		svid := resp.Svids[0].SpiffeId
		if svid != "spiffe://foo.example.com/web/blog" {
			t.Errorf("Got unexpected SpiffeId in response: %s", svid)
		}
		certChain, err := parseCertChain(resp.Svids[0].X509Svid)
		if err != nil {
			t.Fatalf("Could not parse certificate in response: %v", err)
		}
		if len(certChain) == 0 {
			t.Fatalf("Certificate chain had 0 length!")
		}
		leaf := certChain[0]
		if len(leaf.URIs) != 1 || leaf.URIs[0].String() != svid {
			t.Errorf("Got unexpected URI SAN in response: %s", leaf.URIs[0].String())
		}
	})
}

func TestCertsGetRotated(t *testing.T) {
	runInTestEnv(t, func(client workload.SpiffeWorkloadAPIClient) {
		header := metadata.New(map[string]string{"workload.spiffe.io": "true"})
		ctx, cancel := context.WithCancel(metadata.NewOutgoingContext(context.Background(), header))
		stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
		if err != nil {
			t.Fatal(err)
		}
		defer cancel()

		resp1, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		resp2, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}

		certChain1, err := parseCertChain(resp1.Svids[0].X509Svid)
		if err != nil {
			t.Fatal(err)
		}
		certChain2, err := parseCertChain(resp2.Svids[0].X509Svid)
		if err != nil {
			t.Fatal(err)
		}

		// The mock certificate fetcher increments the serial number by one on each pass
		if certChain2[0].SerialNumber.Int64() != certChain1[0].SerialNumber.Int64()+1 {
			t.Error("Got unexpected serial numbers in two responses.")
		}
	})
}

func TestSpiffeAuthorizationHeaderRequired(t *testing.T) {
	runInTestEnv(t, func(client workload.SpiffeWorkloadAPIClient) {
		runTestWithHeaders := func(headers map[string]string) func(t *testing.T) {
			return func(t *testing.T) {
				header := metadata.New(headers)
				ctx, cancel := context.WithCancel(metadata.NewOutgoingContext(context.Background(), header))
				defer cancel()

				stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
				if err != nil {
					t.Fatal(err)
				}
				_, err = stream.Recv()
				if err == nil {
					t.Error("Should have received an error")
				}
				if s, ok := status.FromError(err); !ok {
					t.Errorf("Did not get a status error: %v", err)
				} else {
					if s.Code() != codes.InvalidArgument {
						t.Errorf("Did not get an invalid argument error: %v", err)
					}
				}
			}
		}

		t.Run("empty headers", runTestWithHeaders(map[string]string{}))
		t.Run("header value == false", runTestWithHeaders(map[string]string{"workload.spiffe.io": "false"}))
		// Spec says that header value should be case sensitive
		t.Run("header value == TRUE", runTestWithHeaders(map[string]string{"workload.spiffe.io": "TRUE"}))
	})
}

func parseCertChain(chainBytes []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for len(chainBytes) > 0 {
		var err error
		val := new(asn1.RawValue)
		chainBytes, err = asn1.Unmarshal(chainBytes, val)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(val.FullBytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	return chain, nil
}
