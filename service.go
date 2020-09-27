package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/JackOfMostTrades/spiffe-user-demo/common"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/square/go-jose.v2/jwt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type WorkloadService struct {
	workload.UnimplementedSpiffeWorkloadAPIServer

	logger       *logrus.Logger
	client       UserClient
	shutdownChan chan bool

	newSvidsPubSub *PubSub
}

func NewWorkloadService(refreshFrequency time.Duration, logger *logrus.Logger, client UserClient) *WorkloadService {
	s := &WorkloadService{
		logger:         logger,
		client:         client,
		shutdownChan:   make(chan bool),
		newSvidsPubSub: NewPubSub(),
	}
	go func() {
		runUpdate := func() {
			s.logger.Debug("Fetching updated certificates.")
			err := s.updateResponseAndNotify()
			if err != nil {
				logger.Errorf("failed to fetch new certificates: %v", err)
			} else {
				s.logger.Debug("Certificates successfully updated.")
			}
		}

		// Prime initial data
		runUpdate()

		ticker := time.NewTicker(refreshFrequency)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				runUpdate()
			case <-s.shutdownChan:
				return
			}
		}
	}()

	return s
}

func (s *WorkloadService) Stop() {
	s.shutdownChan <- true
}

func (s *WorkloadService) updateResponseAndNotify() error {
	keypair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(keypair.Public())
	if err != nil {
		return err
	}
	results, err := s.client.GetUserX509(&common.GetUserX509Request{
		PublicKey: pubKeyBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch certificates: %v", err)
	}

	svid, err := certChainToSvid(keypair, results.CertificateChain)
	if err != nil {
		return fmt.Errorf("unable to convert certificate chain in response to SVID: %v", err)
	}

	s.logger.Infof("Sending new certificates to %d subscribers...", s.newSvidsPubSub.GetSubscriberCount())
	s.newSvidsPubSub.Publish([]*workload.X509SVID{svid})

	return nil
}

func certChainToSvid(privateKey crypto.PrivateKey, certChain [][]byte) (*workload.X509SVID, error) {
	leafCert, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate in response: %v", err)
	}

	allCertBytes := make([]byte, 0)
	for _, cert := range certChain {
		allCertBytes = append(allCertBytes, cert...)
	}

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	var spiffeid string
	for _, uri := range leafCert.URIs {
		if strings.ToLower(uri.Scheme) == "spiffe" {
			// If there are multiple spiffe URIs, bail out
			if spiffeid != "" {
				spiffeid = ""
				break
			}
			spiffeid = uri.String()
		}
	}

	return &workload.X509SVID{
		SpiffeId:    spiffeid,
		X509Svid:    allCertBytes,
		X509SvidKey: privKeyBytes,
		Bundle:      certChain[len(certChain)-1],
	}, nil
}

func (s *WorkloadService) FetchX509SVID(req *workload.X509SVIDRequest, srv workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	headers, ok := metadata.FromIncomingContext(srv.Context())
	if !ok {
		return status.Error(codes.InvalidArgument, "Unable to retrieve request context headers.")
	}
	authHeaders := headers.Get("workload.spiffe.io")
	if len(authHeaders) != 1 || authHeaders[0] != "true" {
		return status.Error(codes.InvalidArgument, "SPIFFE workload authentication header is invalid or missing.")
	}

	// If debug logging is enabled, generate a UUID to track this connection and log the connect/disconnect events
	if s.logger.IsLevelEnabled(logrus.DebugLevel) {
		if peerId, err := uuid.NewRandom(); err == nil {
			s.logger.Debugf("Got new subscription for client: %s", peerId)
			defer s.logger.Debugf("Connection to peer %s has been ended.", peerId)
		}
	}

	subscription := s.newSvidsPubSub.Subscribe()
	defer subscription.Close()

	// Channel that indicates the client has cancelled the stream
	done := srv.Context().Done()

	for {
		select {
		case <-done:
			return srv.Context().Err()
		case svids := <-subscription.C:
			// When the channel gets closed (because the server is shutting down gracefully) the channel outputs nil
			if svids == nil {
				return status.Error(codes.Unavailable, "Workload agent is shutting down.")
			}

			if msg, ok := svids.([]*workload.X509SVID); ok {
				err := srv.Send(&workload.X509SVIDResponse{Svids: msg})
				if err != nil {
					return err
				}
			} else {
				s.logger.Errorf("Got unexpected subscription notification: %T", svids)
			}
		}
	}

	// Unreachable
}

func (s *WorkloadService) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	res, err := s.client.GetUserJwt(&common.GetUserJwtRequest{
		Audience: req.Audience,
	})
	if err != nil {
		return nil, err
	}
	token, err := jwt.ParseSigned(res.UserJwt)
	if err != nil {
		return nil, err
	}
	claims := new(jwt.Claims)
	err = token.UnsafeClaimsWithoutVerification(claims)
	if err != nil {
		return nil, err
	}
	svid := &workload.JWTSVID{
		SpiffeId: claims.Subject,
		Svid:     res.UserJwt,
	}
	return &workload.JWTSVIDResponse{
		Svids: []*workload.JWTSVID{svid},
	}, nil
}

func (s *WorkloadService) FetchJWTBundles(req *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	jwks, err := s.client.GetJwks()
	if err != nil {
		return err
	}

	jwksBytes, err := json.Marshal(jwks.Jwks)
	if err != nil {
		return err
	}
	stream.Send(&workload.JWTBundlesResponse{
		Bundles: map[string][]byte{
			jwks.TrustDomain: jwksBytes,
		},
	})

	// Channel that indicates the client has cancelled the stream
	<-stream.Context().Done()
	return stream.Context().Err()
}

type WorkloadServiceServerOptions struct {
	SocketPath       string
	Logger           *logrus.Logger
	Client           UserClient
	RefreshFrequency time.Duration
}

type WorkloadServiceServer struct {
	service   *WorkloadService
	server    *grpc.Server
	stopped   bool
	waitGroup *sync.WaitGroup
	exitErr   error
}

func (s *WorkloadServiceServer) Wait() error {
	s.waitGroup.Wait()
	if s.stopped {
		return nil
	}
	return s.exitErr
}

func (s *WorkloadServiceServer) Stop() error {
	s.stopped = true
	s.server.Stop()
	s.service.Stop()
	return nil
}

func StartWorkloadServiceServer(options *WorkloadServiceServerOptions) (*WorkloadServiceServer, error) {
	if _, err := os.Stat(options.SocketPath); err == nil {
		err = os.Remove(options.SocketPath)
		if err != nil {
			return nil, fmt.Errorf("Socket path %s already exists but could not be removed.", options.SocketPath)
		}
	}
	lis, err := net.Listen("unix", options.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on socket path %s: %v", options.SocketPath, err)
	}

	service := NewWorkloadService(options.RefreshFrequency, options.Logger, options.Client)

	server := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(server, service)
	wg := new(sync.WaitGroup)
	wg.Add(1)

	s := &WorkloadServiceServer{
		service:   service,
		server:    server,
		stopped:   false,
		waitGroup: wg,
		exitErr:   nil,
	}

	go func() {
		s.exitErr = server.Serve(lis)
		s.waitGroup.Add(-1)
	}()

	return s, nil
}
