package commands

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/pterm/pterm"
	"github.com/sanjaynagpal/go-learn/waverly/app-auth-client/logger"
	"golang.org/x/oauth2"
)

type Common struct {
	Verbose bool `name:"verbose" description:"Enable verbose output"`
	NoColor bool `name:"no-color" description:"Disable colored output"`
}
type AuthCommand struct {
	Common
	ClientID   string `name:"clientid" description:"Client ID for authentication"`
	TenantID   string `name:"tenantid" description:"Tenant ID for authentication"`
	ListenAddr string `name:"listenaddr" description:"Port to run the client on" default:"8080"`
}

var (
	oauthConfig *oauth2.Config
)

// Authentication App
func AuthApp(cmd *AuthCommand) error {
	// Implement the processing logic here
	pterm.DefaultSection.Println("Starting Authentication App...")
	if cmd.Verbose {
		pterm.Info.Println("Verbose mode is enabled.")
	}
	logger, err := logger.InitFileLogger("waverly_auth_client")
	if err != nil {
		log.Fatal("Failed to initialize logger:", err)
	}
	logger.Info().Msg("Authentication App started.")
	if cmd.ClientID != "" {
		logger.Info().Str("client_id", cmd.ClientID).Msg("🆔Using provided Client ID.")
	}
	if cmd.TenantID != "" {
		logger.Info().Str("tenant_id", cmd.TenantID).Msg("🏠Using provided Tenant ID.")
	}
	if cmd.ListenAddr != "" {
		logger.Info().Str("listen_addr", cmd.ListenAddr).Msg("📡Using provided Listen Address.")
	}

	// Set up HTTP server
	router := mux.NewRouter()

	// Routes
	router.HandleFunc("/", homeHandler).Methods("GET")

	logger.Info().Msg("Router initialized with routes.")

	// Further implementation goes here
	pterm.Success.Println("Authentication App finished successfully.")

	return nil
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to the Waverly Auth Client!"))
}
