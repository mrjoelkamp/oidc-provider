package op

// Config holds the configuration for the OP
// TODO: expand and make configurable as args
type Config struct {
	Host     string
	Port     string
	LogLevel string
	KeyPath  string
	Issuer   string
}
