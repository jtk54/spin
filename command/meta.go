// Copyright (c) 2018, Google, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package command

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	_ "net/http/pprof"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/mitchellh/cli"
	"github.com/mitchellh/colorstring"
	"github.com/mitchellh/go-homedir"
	"github.com/spinnaker/spin/config"
	gate "github.com/spinnaker/spin/gateapi"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

// ApiMeta is the state & utility shared by our commands.
type ApiMeta struct {
	// The exported fields below should be set by anyone using a command
	// with an ApiMeta field. These are expected to be set externally
	// (not from within the command itself).

	Color bool   // True if output should be colored
	Ui    cli.Ui // Ui for output

	// Gate Api client.
	GateClient *gate.APIClient

	// Spin CLI configuration.
	Config config.Config

	// Context for OAuth2 access token.
	Context context.Context

	// Internal fields
	color bool

	// This is the set of flags global to the command parser.
	gateEndpoint string

	insecure bool

	// Location of the spin config.
	configLocation string
}

// GlobalFlagSet adds all global options to the flagset, and returns the flagset object
// for further modification by the subcommand.
func (m *ApiMeta) GlobalFlagSet(cmd string) *flag.FlagSet {
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)

	f.StringVar(&m.gateEndpoint, "gate-endpoint", "http://localhost:8084",
		"Gate (API server) endpoint")

	f.BoolVar(&m.insecure, "insecure", false, "Ignore Certificate Errors")

	f.Usage = func() {}

	return f
}

// Process will process the meta-parameters out of the arguments. This
// potentially modifies the args in-place. It will return the resulting slice.
// NOTE: This expects the flag set to be parsed prior to invoking it.
func (m *ApiMeta) Process(args []string) ([]string, error) {
	// Do the Ui initialization so we can properly warn if Process() fails.
	// Colorization.
	m.Color = true
	m.color = m.Color
	for i, v := range args {
		if v == "--no-color" {
			m.color = false
			m.Color = false
			args = append(args[:i], args[i+1:]...)
			break
		}
	}

	// Set the Ui.
	m.Ui = &ColorizeUi{
		Colorize:   m.Colorize(),
		ErrorColor: "[red]",
		WarnColor:  "[yellow]",
		InfoColor:  "[blue]",
		Ui:         &cli.BasicUi{Writer: os.Stdout},
	}

	// CLI configuration.
	usr, err := user.Current()
	if err != nil {
		m.Ui.Error(fmt.Sprintf("Could not read current user from environment, failing."))
		return args, err
	}

	m.configLocation = filepath.Join(usr.HomeDir, ".spin", "config")
	yamlFile, err := ioutil.ReadFile(m.configLocation)
	if err != nil {
		m.Ui.Warn(fmt.Sprintf("Could not read configuration file from %s.", m.configLocation))
	}

	if yamlFile != nil {
		err = yaml.UnmarshalStrict(yamlFile, &m.Config)
		if err != nil {
			m.Ui.Error(fmt.Sprintf("Could not deserialize config file with contents: %d, failing.", yamlFile))
			return args, err
		}
	} else {
		m.Config = config.Config{}
	}

	// Api client initialization.
	err = m.Authenticate()
	if err != nil {
		m.Ui.Error(fmt.Sprintf("OAuth2 Authentication failed."))
		return args, err
	}

	client, err := m.InitializeClient()
	if err != nil {
		m.Ui.Error(fmt.Sprintf("Could not initialize http client, failing."))
		return args, err
	}

	cfg := &gate.Configuration{
		BasePath:      m.gateEndpoint,
		DefaultHeader: make(map[string]string),
		UserAgent:     "Spin CLI version", // TODO(jacobkiefer): Add a reasonable UserAgent.
		HTTPClient:    client,
	}
	m.GateClient = gate.NewAPIClient(cfg)

	return args, nil
}

// Colorize initializes the ui colorization.
func (m *ApiMeta) Colorize() *colorstring.Colorize {
	return &colorstring.Colorize{
		Colors:  colorstring.DefaultColors,
		Disable: !m.color,
		Reset:   true,
	}
}

func (m *ApiMeta) InitializeClient() (*http.Client, error) {
	auth := m.Config.Auth
	cookieJar, _ := cookiejar.New(nil)
	client := http.Client{
		Jar: cookieJar,
	}

	if auth != nil && auth.Enabled && auth.X509 != nil {
		X509 := auth.X509
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{},
		}

		if !X509.IsValid() {
			// Misconfigured.
			return nil, errors.New("Incorrect x509 auth configuration.\nMust specify certPath/keyPath or cert/key pair.")
		}

		if X509.CertPath != "" && X509.KeyPath != "" {
			tlsConfig, err := m.initializeTLSFromPath(X509.CertPath, X509.KeyPath)
			if err != nil {
				return nil, err
			}
			client.Transport.(*http.Transport).TLSClientConfig = tlsConfig
			return &client, nil
		} else if X509.Cert != "" && X509.Key != "" {
			certBytes := []byte(X509.Cert)
			keyBytes := []byte(X509.Key)
			cert, err := tls.X509KeyPair(certBytes, keyBytes)
			if err != nil {
				return nil, err
			}

			tlsConfig := m.initializeTLSFromCert(certBytes, cert)
			client.Transport.(*http.Transport).TLSClientConfig = tlsConfig
			return &client, nil
		} else {
			// Misconfigured.
			return nil, errors.New("Incorrect x509 auth configuration.\nMust specify certPath/keyPath or cert/key pair.")
		}
	} else if auth != nil && auth.Enabled && auth.Basic != nil {
		if !auth.Basic.IsValid() {
			return nil, errors.New("Incorrect Basic auth configuration. Must include username and password.")
		}
		m.Context = context.WithValue(context.Background(), gate.ContextBasicAuth, gate.BasicAuth{
			UserName: auth.Basic.Username,
			Password: auth.Basic.Password,
		})
		return &client, nil
	} else {
		return &client, nil
	}
}

func (m *ApiMeta) initializeTLSFromPath(certPath string, keyPath string) (*tls.Config, error) {
	certFullPath, err := homedir.Expand(certPath)
	if err != nil {
		return nil, err
	}
	keyFullPath, err := homedir.Expand(keyPath)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFullPath, keyFullPath)
	if err != nil {
		return nil, err
	}

	clientCA, err := ioutil.ReadFile(certFullPath)
	if err != nil {
		return nil, err
	}

	return m.initializeTLSFromCert(clientCA, cert), nil
}

func (m *ApiMeta) initializeTLSFromCert(clientCA []byte, cert tls.Certificate) *tls.Config {
	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCA)

	return &tls.Config{
		Certificates:             []tls.Certificate{cert},
		ClientCAs:                clientCertPool,
		InsecureSkipVerify:       m.insecure,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
}

func (m *ApiMeta) Authenticate() error {
	auth := m.Config.Auth
	if auth != nil && auth.Enabled && auth.OAuth2 != nil {
		var newToken *oauth2.Token
		var err error
		var tlsConfig *tls.Config
		var certPath, keyPath string

		OAuth2 := auth.OAuth2
		if !OAuth2.IsValid() {
			// TODO(jacobkiefer): Improve this error message.
			return errors.New("Incorrect OAuth2 auth configuration.")
		}

		redirectUrl := "http://localhost:8085"
		sslEnabled := OAuth2.SslConfig != nil
		if sslEnabled {
			redirectUrl = "https://localhost:8085"
			certPath, err := homedir.Expand(OAuth2.SslConfig.CertPath)
			keyPath, err := homedir.Expand(OAuth2.SslConfig.KeyPath)
			tlsConfig, err = m.initializeTLSFromPath(certPath, keyPath)
			if err != nil {
				return err
			}
		}

		config := &oauth2.Config{
			ClientID:     OAuth2.ClientId,
			ClientSecret: OAuth2.ClientSecret,
			RedirectURL:  redirectUrl,
			Scopes:       OAuth2.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  OAuth2.AuthUrl,
				TokenURL: OAuth2.TokenUrl,
			},
		}

		cookieJar, _ := cookiejar.New(nil)
		client := &http.Client{
			Jar:       cookieJar,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		}
		oauthContext := context.WithValue(context.Background(), oauth2.HTTPClient, client)

		if auth.OAuth2.CachedToken != nil {
			// Look up cached credentials to save oauth2 roundtrip.
			token := auth.OAuth2.CachedToken
			tokenSource := config.TokenSource(oauthContext, token)
			newToken, err = tokenSource.Token()
			if err != nil {
				m.Ui.Error(fmt.Sprintf("Could not refresh token from source: %v", tokenSource))
				return err
			}
		} else {
			// Do roundtrip.
			if sslEnabled {
				srv := &http.Server{
					Addr:      ":8085",
					Handler:   &handler{},
					TLSConfig: tlsConfig,
				}
				go srv.ListenAndServeTLS(certPath, keyPath)
			} else {
				srv := &http.Server{
					Addr:    ":8085",
					Handler: &handler{},
				}
				go srv.ListenAndServe()
			}
			// Note: leaving server connection open for scope of request, will be reaped on exit.

			authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
			m.Ui.Output(fmt.Sprintf("Navigate to %s and authenticate", authURL))
			code := m.Prompt()

			newToken, err = config.Exchange(oauthContext, code)
			if err != nil {
				return err
			}
		}

		m.Ui.Output("Caching oauth2 token.")
		OAuth2.CachedToken = newToken
		buf, _ := yaml.Marshal(&m.Config)
		info, _ := os.Stat(m.configLocation)
		ioutil.WriteFile(m.configLocation, buf, info.Mode())
		m.Context = context.WithValue(context.Background(), gate.ContextAccessToken, newToken.AccessToken)
	}
	return nil
}

// handler is an HTTP handler to
type handler struct{}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	fmt.Fprintln(w, code)
}

func (m *ApiMeta) Prompt() string {
	reader := bufio.NewReader(os.Stdin)
	m.Ui.Output(fmt.Sprintf("Paste authorization code:"))
	text, _ := reader.ReadString('\n')
	return text
}

func (m *ApiMeta) Help() string {
	help := `
Global Options:

	--gate-endpoint               Gate (API server) endpoint.
        --no-color                    Removes color from CLI output.
        --insecure=false              Ignore certificate errors during connection to endpoints.
	`

	return strings.TrimSpace(help)
}
