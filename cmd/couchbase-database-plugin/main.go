package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"

	couchbase "github.com/hashicorp/vault-plugin-database-couchbase"
	"github.com/hashicorp/vault/api"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	err := Run()
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})

		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}

// Run instantiates a CouchbaseDB object, and runs the RPC server for the plugin
func Run() error {
	db, err := couchbase.New()
	if err != nil {
		return err
	}

	dbplugin.Serve(db.(dbplugin.Database))

	return nil
}
