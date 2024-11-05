package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/gorilla/mux"
)

const (
	PORT_ENV                 = "PORT"
	INFERENCE_SERVER_URL_ENV = "INFERENCE_SERVER_URL"
)

type Server struct {
	decryptionServerURL string
	client              *http.Client
	publicKeys          map[string]x448.Key // instanceID -> publicKey
	keyMutex            sync.RWMutex
}

type PublicKeyResponse struct {
	PublicKey string `json:"publicKey"`
	ServerID  string `json:"serverId"`
	ExpiresAt string `json:"expiresAt"`
}

type ChatCompletionRequest struct {
	Stream bool `json:"stream"`
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	inferenceServerURL := strings.TrimSuffix(os.Getenv(INFERENCE_SERVER_URL_ENV), "/")
	if inferenceServerURL == "" {
		inferenceServerURL = "https://api.getfluid.app"
	}

	server := &Server{
		decryptionServerURL: inferenceServerURL,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		publicKeys: make(map[string]x448.Key),
	}

	r := mux.NewRouter()
	r.HandleFunc("/v1/chat/completions", server.handleChatCompletions).Methods("POST")
	r.HandleFunc("/v1/models", server.handleModels).Methods("GET")

	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("ERROR: No route found for %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})

	port := os.Getenv(PORT_ENV)
	if port == "" {
		port = "2222" // use default port if PORT env variable is not set
	}

	log.Printf("Using %s as your inference endpoint", inferenceServerURL)
	log.Printf("Starting encryption server on port %s (%s)", port, "http://localhost:2222/v1")
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func setAuthHeader(source *http.Request, dest *http.Request) {
	if authHeader := source.Header.Get("Authorization"); authHeader != "" {
		dest.Header.Set("Authorization", authHeader)
	}
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling request: %s %s", r.Method, r.URL)

	req, err := http.NewRequest("GET", s.decryptionServerURL+"/v1/models", nil)
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	setAuthHeader(r, req)

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("Failed to get models from inference server: %v", err)
		http.Error(w, "Failed to reach backend server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		http.Error(w, "Failed to process response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling request: %s %s", r.Method, r.URL)

	requestBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var chatRequest ChatCompletionRequest
	if err := json.Unmarshal(requestBody, &chatRequest); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// get public key from decryption server
	var inferenceServerPublicKey x448.Key
	var serverNo string
	serverNo, inferenceServerPublicKey, err = s.getDecryptionServerPublicKey(r.Header.Get("Authorization"))
	if err != nil {
		log.Printf("Failed to get decryption server public key: %v", err)
		http.Error(w, "Failed to establish secure connection", http.StatusServiceUnavailable)
		return
	}

	var clientKeyPair *KeyPair
	clientKeyPair, err = GenerateNewKeyPair()
	if err != nil {
		log.Printf("Failed to generate new key pair: %v", err)
		http.Error(w, "Failed to establish secure connection", http.StatusServiceUnavailable)
		return
	}

	sharedSecretKey, err := DeriveSharedSecret(clientKeyPair.PrivateKey, inferenceServerPublicKey)
	if err != nil {
		log.Printf("Failed to derive shared secret: %v", err)
		http.Error(w, "Failed to establish secure connection", http.StatusServiceUnavailable)
		return
	}

	encryptedData, err := CompressAndEncryptAES(requestBody, sharedSecretKey)
	if err != nil {
		log.Printf("Failed to encrypt request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	chatCompletionReq, err := http.NewRequest("POST", s.decryptionServerURL+"/v1/chat/completions", bytes.NewReader(encryptedData))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	chatCompletionReq.Header.Set("Content-Type", "application/json")
	chatCompletionReq.Header.Set("Accept", "text/event-stream")
	chatCompletionReq.Header.Set("X-Client-Public-Key", fmt.Sprintf(`{"%s": "%s"}`, serverNo, base64.StdEncoding.EncodeToString(clientKeyPair.PublicKey[:])))
	setAuthHeader(r, chatCompletionReq)

	resp, err := s.client.Do(chatCompletionReq)
	if err != nil {
		log.Printf("Failed to forward request: %v", err)
		http.Error(w, "Failed to reach backend server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if chatRequest.Stream {
		s.handleStreamingResponse(w, resp, sharedSecretKey)
	} else {
		s.handleNonStreamingResponse(w, resp, sharedSecretKey)
	}
}

func (s *Server) handleStreamingResponse(w http.ResponseWriter, resp *http.Response, secret []byte) {
	w.Header().Set("Content-Type", "text/event-stream")

	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Printf("Streaming unsupported")
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading stream: %v", err)
			}
			return
		}

		// for encrypted responses, we need to decode base64 first, unless it's newline
		if len(line) > 0 {
			if line[0] != '\n' {
				decodedLine, err := base64.StdEncoding.DecodeString(string(line))
				if err != nil {
					log.Printf("Failed to decode base64: %v", err)
					continue
				}

				decryptedLine, err := DecryptAndDecompressAES(decodedLine, secret)
				if err != nil {
					log.Printf("Failed to decrypt: %v", err)
					continue
				}
				w.Write(decryptedLine)
			}
			w.Write([]byte("\n"))
			flusher.Flush()
		}
	}
}

func (s *Server) handleNonStreamingResponse(w http.ResponseWriter, resp *http.Response, secret []byte) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	decryptedBody, err := DecryptAndDecompressAES(body, secret)
	if err != nil {
		log.Printf("Failed to decrypt response: %v", err)
		http.Error(w, "Failed to process response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(decryptedBody)
}

func (s *Server) getDecryptionServerPublicKey(authHeader string) (string, x448.Key, error) {
	req, err := http.NewRequest("GET", s.decryptionServerURL+"/public-key", nil)
	if err != nil {
		return "", x448.Key{}, fmt.Errorf("failed to create request: %v", err)
	}

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", x448.Key{}, fmt.Errorf("failed to get public key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", x448.Key{}, fmt.Errorf("failed to get public key: server returned status %d: %s",
			resp.StatusCode, string(body))
	}

	var keyResp PublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return "", x448.Key{}, fmt.Errorf("failed to decode response: %v", err)
	}

	decodedKey, err := base64.StdEncoding.DecodeString(keyResp.PublicKey)
	if err != nil {
		return "", x448.Key{}, fmt.Errorf("failed to decode public key: %v", err)
	}

	var key x448.Key
	copy(key[:], decodedKey)
	return keyResp.ServerID, key, nil
}
