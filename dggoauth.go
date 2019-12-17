package dggoauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/dchest/uniuri"
)

const (
	// AuthURL ...
	AuthURL = "https://www.destiny.gg/oauth/authorize"
	// TokenURL ...
	TokenURL = "https://www.destiny.gg/oauth/token"
)

// Client ...
type Client struct {
	// mu   sync.Mutex
	opts *Options
}

// Options ...
type Options struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	HTTPClient   *http.Client
}

// OauthError ...
type OauthError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// NewClient ...
func NewClient(options *Options) (*Client, error) {
	if options.ClientID == "" {
		return nil, errors.New("A client ID was not provided but is required")
	}
	if options.ClientSecret == "" {
		return nil, errors.New("A client secret was not provided but is required")
	}
	if options.RedirectURI == "" {
		return nil, errors.New("A redirect uri was not provided but is required")
	}

	if options.HTTPClient == nil {
		options.HTTPClient = http.DefaultClient
	}
	return &Client{
		opts: options,
	}, nil
}

func (c *Client) generateCodeChallenge(verifier string) string {
	secret := fmt.Sprintf("%x", sha256.Sum256([]byte(c.opts.ClientSecret)))
	v := []byte(verifier + secret)
	sum := fmt.Sprintf("%x", sha256.Sum256(v))
	return base64.StdEncoding.EncodeToString([]byte(sum))
}

// GetAuthorizationURL returns the authorization url you need to redirect the user to
func (c *Client) GetAuthorizationURL(state string) (url string, verifier string) {
	// min lenght for verifier is 43
	verifier = uniuri.NewLen(45)
	challenge := c.generateCodeChallenge(verifier)
	url = fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&state=%s&code_challenge=%s",
		AuthURL,
		c.opts.ClientID,
		c.opts.RedirectURI,
		state,
		challenge,
	)
	return url, verifier
}

// AccessTokenResponse ...
type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// GetAccessToken returns the access token with the code and verifier provided
func (c *Client) GetAccessToken(code, verifier string) (*AccessTokenResponse, error) {
	s := fmt.Sprintf("%s?grant_type=authorization_code&code=%s&client_id=%s&redirect_uri=%s&code_verifier=%s",
		TokenURL,
		code,
		c.opts.ClientID,
		c.opts.RedirectURI,
		verifier,
	)

	response, err := c.opts.HTTPClient.Get(s)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		var oe OauthError
		err := json.NewDecoder(response.Body).Decode(&oe)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("error getting access_token, code: %d, message: %s, err: %s", oe.Code, oe.Message, oe.Error)
	}

	var accessToken AccessTokenResponse
	err = json.NewDecoder(response.Body).Decode(&accessToken)
	return &accessToken, err
}

// RenewAccessToken renews the access token with the refresh token provided
func (c *Client) RenewAccessToken(refreshToken string) (*AccessTokenResponse, error) {
	s := fmt.Sprintf("%s?grant_type=refresh_token&client_id=%s&refresh_token=%s",
		TokenURL,
		c.opts.ClientID,
		refreshToken,
	)

	response, err := c.opts.HTTPClient.Get(s)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		var oe OauthError
		err := json.NewDecoder(response.Body).Decode(&oe)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("error renewing access_token, code: %d, message: %s, err: %s", oe.Code, oe.Message, oe.Error)
	}

	var accessToken AccessTokenResponse
	err = json.NewDecoder(response.Body).Decode(&accessToken)
	return &accessToken, err
}
