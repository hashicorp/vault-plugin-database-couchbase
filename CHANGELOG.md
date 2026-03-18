## Unreleased
## v0.16.0
### March 16, 2026

IMPROVEMENTS:
* Updated dependencies:
  * go 1.25.1 => 1.26.1
  * google.golang.org/genproto/googleapis/rpc v0.0.0-20250811230008-5f3141c8851a => v0.0.0-20250929231259-57b25ae835d4
  * github.com/hashicorp/vault/sdk v0.19.0 => v0.23.0
  * golang.org/x/mod v0.28.0 => v0.31.0
  * golang.org/x/text v0.28.0 => v0.33.0
  * golang.org/x/oauth2 v0.30.0 => v0.31.0
  * golang.org/x/sys v0.35.0 => v0.40.0
  * golang.org/x/crypto v0.41.0 => v0.47.0
  * golang.org/x/net v0.43.0 => v0.49.0
  * cloud.google.com/go/compute/metadata v0.7.0 => v0.9.0
  * go.opentelemetry.io/auto/sdk v1.1.0 => v1.2.1
  * google.golang.org/protobuf v1.36.7 => v1.36.11
  * go.opentelemetry.io/otel v1.37.0 => v1.40.0
  * go.opentelemetry.io/otel/metric v1.37.0 => v1.40.0
  * go.opentelemetry.io/otel/trace v1.37.0 => v1.40.0
  * google.golang.org/grpc v1.74.2 => v1.75.1

## v0.15.0
### October 2, 2025

* Bump go version to 1.25.1 (#107)
* Automated dependency upgrades (#99)
* [COMPLIANCE] Add Copyright and License Headers (#106)
* Bump github.com/go-viper/mapstructure/v2 from 2.1.0 to 2.4.0 (#104)
* init changie (#105)
* Add backport assistant workflow (#102)
* Add backport assistant workflow (#101)
* [Compliance] - PR Template Changes Required (#100)

## v0.14.0
### Jun 3, 2025

IMPROVEMENTS:
* Updated dependencies:
  * Go version: 1.23.6 -> 1.24.3
  * `github.com/couchbase/gocb/v2` v2.9.3 -> v2.10.0
  * `github.com/hashicorp/vault/sdk` v0.14.1 -> v0.17.0
  * `github.com/ory/dockertest/v3` v3.11.0 -> v3.12.0
  * `golang.org/x/mod` v0.22.0 -> v0.24.0

## v0.13.0
### Feb 7, 2025

IMPROVEMENTS:
* Updated dependencies: 
  * (https://github.com/hashicorp/vault-plugin-database-couchbase/pull/89)
  * (https://github.com/hashicorp/vault-plugin-database-couchbase/pull/92)

## v0.12.0
### Sept 4, 2024

IMPROVEMENTS:
* Updated dependencies: (https://github.com/hashicorp/vault-plugin-database-couchbase/pull/80)

BUG FIXES:
* allow custom username templates to use the lowercase function (https://github.com/hashicorp/vault-plugin-database-couchbase/pull/81)

## v0.11.0
IMPROVEMENTS:
* Updated dependencies:
  * `github.com/jackc/pgx/v4` v4.18.1 -> v4.18.2
  * `google.golang.org/protobuf` v1.32.0 -> v1.33.0
  * `github.com/hashicorp/go-plugin` v1.5.2 to -> v1.6.0

## v0.10.1
* Revert dependency update causing build failures on 32-bit systems
  * github.com/couchbase/gocb/v2 v2.7.1 -> v2.6.5

## v0.10.0
* Updated dependencies:
  * github.com/couchbase/gocb/v2 v2.6.3 -> v2.6.5
  * github.com/hashicorp/go-hclog v1.5.0 -> v1.6.2
  * github.com/hashicorp/vault/sdk v0.10.0 -> v0.10.2
  * golang.org/x/mod v0.12.0 -> v0.15.0
  * github.com/opencontainers/runc v1.1.6 -> v1.1.12
  * github.com/docker/docker v24.0.5+incompatible -> v24.0.9+incompatible

## v0.9.4

IMPROVEMENTS:
* Updated indirect dependency `golang.org/x/net` v0.9.0 -> v0.15.0 due to vulnerability GO-2023-1988 v0.9.0

## v0.9.3

IMPROVEMENTS:

* Updated dependencies:
  * `github.com/hashicorp/vault/sdk` v0.9.0 -> v0.10.0
  * `github.com/stretchr/testify` v1.8.3 -> v1.8.4
  * `golang.org/x/mod` v0.9.0 -> v0.12.0

## v0.9.2

CHANGES:
* Renaming  `cmd/couchbase-database-plugin/main.go` to `cmd/vault-plugin-database-couchbase/main.go` [[GH-50](https://github.com/hashicorp/vault-plugin-database-couchbase/pull/50)]

## v0.9.1

IMPROVEMENTS:
* Updated dependencies:
   * `github.com/couchbase/gocb/v2` v2.3.3 -> v2.6.3
   * `github.com/hashicorp/go-hclog` v1.0.0 -> v1.5.0
   * `github.com/hashicorp/go-version` v1.3.0 -> v1.6.0
   * `github.com/hashicorp/vault/sdk` v0.5.3 -> v0.9.0
   * `github.com/ory/dockertest/v3` v3.8.0 -> v3.10.0
   * `github.com/stretchr/testify` v1.7.0 -> v1.8.3
   * `golang.org/x/mod` v0.9.0 added
