package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"

	couchbase "github.com/fhitchen/vault-plugin-database-couchbase"
	"github.com/hashicorp/vault/api"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	err := couchbase.Run(apiClientMeta.GetTLSConfig())
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})

		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
