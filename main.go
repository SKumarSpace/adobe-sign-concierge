package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	_ "embed"

	"github.com/jessevdk/go-flags"
)

type Arguments struct {
	Shard        string `required:"true" long:"shard" description:"Shard value"`
	ClientID     string `required:"true" long:"clientId" description:"Client ID"`
	ClientSecret string `required:"true" long:"clientSecret" description:"Client Secret"`
	Scope        string `required:"true" long:"scope" description:"Scope"`
}

/*
	{
	    "error_description": "invalid authorization code",
	    "error": "invalid_request"
	}
*/
type AdobeTokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

/*
	{
	    "access_token": "3A*****************************************",
	    "refresh_token": "3AA***************************************",
	    "api_access_point": "https://api.na4.adobesign.com/",
	    "web_access_point": "https://secure.na4.adobesign.com/",
	    "token_type": "Bearer",
	    "expires_in": 3600
	}
*/
type AdobeTokenSuccessResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

var redirectUrl = "https://localhost:9000"

//go:embed server.crt
var cert []byte

//go:embed server.key
var key []byte

func main() {
	// Parse command line arguments
	var args Arguments
	_, err := flags.Parse(&args)
	if err != nil {
		slog.Error(fmt.Sprintf("Error parsing arguments: %v", err))
		return
	}

	adobeRequestUrl := getAdobeRequestUrl(args, redirectUrl)
	slog.Info(fmt.Sprintf("Adobe Request URL: %s", adobeRequestUrl))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Code not found in the URL", http.StatusBadRequest)
			return
		}

		slog.Info(fmt.Sprintf("Code: %s", code))

		accessToken, refreshToken, err := getAdobeAccessTokens(args, code)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error getting access tokens: %v", err), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Access Token: %s, Refresh Token: %s", accessToken, refreshToken)
		slog.Info(fmt.Sprintf("Access Tokne: %s", accessToken))
		slog.Info(fmt.Sprintf("Refresh Token: %s", refreshToken))
	})

	cert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		slog.Error(fmt.Sprintf("Error loading certificate: %v", err))
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &http.Server{
		Addr:      ":9000",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		slog.Error(fmt.Sprintf("Error serving requests: %v", err))
	}
}

func getAdobeRequestUrl(args Arguments, redirectUrl string) string {
	// Split the scope into individual scopes
	scopesArr := strings.Split(args.Scope, ",")
	scopes := strings.Join(scopesArr, "+")
	fmt.Println("Scopes:", scopes)
	return fmt.Sprintf("https://secure.%s.echosign.com/public/oauth/v2?redirect_uri=%s&response_type=%s&client_id=%s&scope=%s",
		args.Shard, redirectUrl, "code", args.ClientID, scopes)
}

func getAdobeAccessTokens(args Arguments, code string) (string, string, error) {
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {args.ClientID},
		"client_secret": {args.ClientSecret},
		"redirect_uri":  {redirectUrl},
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", fmt.Sprintf("https://secure.%s.echosign.com/oauth/v2/token", args.Shard), strings.NewReader(formData.Encode()))
	if err != nil {
		return "", "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}

	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	if resp.StatusCode != http.StatusOK {
		var errorResponse AdobeTokenErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			return "", "", err
		}

		return "", "", fmt.Errorf("error: %s, description: %s", errorResponse.Error, errorResponse.ErrorDescription)
	}

	var successResponse AdobeTokenSuccessResponse
	err = json.Unmarshal(body, &successResponse)
	if err != nil {
		return "", "", err
	}

	return successResponse.AccessToken, successResponse.RefreshToken, nil
}
