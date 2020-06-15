# vault-plugin-database-couchbase

A [Vault](https://www.vaultproject.io) plugin for Couchbase

This project uses the database plugin interface introduced in Vault version 0.7.1.

## Build

For linux/amd64, pre-built binaries can be found at [the releases page](https://releases.hashicorp.com/vault-plugin-database-couchbase/) (built with the Couchbase Go SDK version 2.1.1)

For other platforms, there are not currently pre-built binaries available.

To build this package for any platform you will need to clone this repository and cd into the repo directory and `go build -o couchbase-database-plugin ./couchbase-database-plugin/`. To test `go test` will execute a set of basic tests against against a custom Docker version of Couchbase (fhitchen/vault-couchbase this will be replaced with an uncustomised latest version of Couchbase when the database customization can be directly done from the test suite). If you want to run the tests against an already running couchbase instance, set the environment variable COUCHBASE_HOST before executing. Set VAULT_ACC to execute all of the tests.

## Installation

The Vault plugin system is documented on the [Vault documentation site](https://www.vaultproject.io/docs/internals/plugins.html).

You will need to define a plugin directory using the `plugin_directory` configuration directive, then place the
`vault-plugin-database-couchbase` executable generated above, into the directory.

Sample commands for registering and starting to use the plugin:

```
$ SHA256=$(shasum -a 256 plugins/couchbase-database-plugin | cut -d' ' -f1)

$ vault secrets enable database

$ vault write sys/plugins/catalog/database/couchbase-database-plugin sha256=$SHA256 \
        command=couchbase-database-plugin
```
