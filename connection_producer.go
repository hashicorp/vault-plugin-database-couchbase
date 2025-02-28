// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package couchbase

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/database/helper/cacheutil"
	"strings"
	"sync"

	"github.com/couchbase/gocb/v2"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/mitchellh/mapstructure"
)

const (
	maxOpenConnections = 4
)

type couchbaseDBConnectionProducer struct {
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
	ProjectID   string `json:"project_id"`
	Hosts       string `json:"hosts"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	TLS         bool   `json:"tls"`
	InsecureTLS bool   `json:"insecure_tls"`
	Base64Pem   string `json:"base64pem"`
	BucketName  string `json:"bucket_name"`
	SelfManaged bool   `json:"self_managed"`

	Initialized         bool
	rawConfig           map[string]interface{}
	Type                string
	cluster             *gocb.Cluster
	staticAccountsCache *cacheutil.Cache
	sync.RWMutex
}

func (c *couchbaseDBConnectionProducer) secretValues() map[string]string {
	return map[string]string{
		c.Password: "[password]",
		c.Username: "[username]",
	}
}

func (c *couchbaseDBConnectionProducer) Init(ctx context.Context, initConfig map[string]interface{}, verifyConnection bool) (saveConfig map[string]interface{}, err error) {
	// Don't let anyone read or write the config while we're using it
	c.Lock()
	defer c.Unlock()

	c.rawConfig = initConfig

	decoderConfig := &mapstructure.DecoderConfig{
		Result:           c,
		WeaklyTypedInput: true,
		TagName:          "json",
	}

	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return nil, err
	}

	err = decoder.Decode(initConfig)
	if err != nil {
		return nil, err
	}

	switch {
	case len(c.Hosts) == 0:
		return nil, fmt.Errorf("hosts cannot be empty")
	case len(c.Username) == 0:
		if c.SelfManaged {
			// TODO pre-emptively added for middleware requirements
			c.Username = "username"
		} else {
			return nil, fmt.Errorf("username cannot be empty")
		}
	case len(c.Password) == 0:
		if c.SelfManaged {
			c.Password = "password"
		} else {
			return nil, fmt.Errorf("password cannot be empty")
		}
	}

	if c.TLS {
		if len(c.Base64Pem) == 0 {
			return nil, fmt.Errorf("base64pem cannot be empty")
		}

		if !strings.HasPrefix(c.Hosts, "couchbases://") {
			return nil, fmt.Errorf("hosts list must start with couchbases:// for TLS connection")
		}
	}

	c.Initialized = true

	if c.SelfManaged && c.staticAccountsCache == nil {
		logger := log.New(&log.LoggerOptions{
			Mutex: &sync.Mutex{},
		})

		closer := func(key interface{}, value interface{}) {
			logger.Debug(fmt.Sprintf("Evicting key %s from static LRU cache", key))
			conn, ok := value.(*gocb.Cluster)
			if !ok {
				// TODO
			}
			if err := conn.Close(&gocb.ClusterCloseOptions{}); err != nil {
				//TODO
			}
			logger.Debug(fmt.Sprintf("Closed DB connection for %s", key))
		}
		c.staticAccountsCache, err = cacheutil.NewCache(maxOpenConnections, closer)

		if err != nil {
			return nil, fmt.Errorf("error initializing static account cache: %s", err)
		}
	}

	if verifyConnection && !c.SelfManaged {
		if _, err := c.Connection(ctx); err != nil {
			c.close()
			return nil, errwrap.Wrapf("error verifying connection: {{err}}", err)
		}
	}

	return initConfig, nil
}

func (c *couchbaseDBConnectionProducer) Initialize(ctx context.Context, config map[string]interface{}, verifyConnection bool) error {
	_, err := c.Init(ctx, config, verifyConnection)
	return err
}

func (c *couchbaseDBConnectionProducer) Connection(ctx context.Context) (interface{}, error) {
	// This is intentionally not grabbing the lock since the calling functions
	// (e.g. CreateUser) are claiming it.

	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	if c.cluster != nil {
		return c.cluster, nil
	}
	sec, err := c.getSecurityConfig()
	if err != nil {
		return nil, err
	}

	c.cluster, err = gocb.Connect(
		c.Hosts,
		gocb.ClusterOptions{
			Username:       c.Username,
			Password:       c.Password,
			SecurityConfig: sec,
		})
	if err != nil {
		return nil, errwrap.Wrapf("error in Connection: {{err}}", err)
	}

	// For databases 6.0 and earlier, we will need to open a `Bucket instance before connecting to any other
	// HTTP services such as UserManager.
	if err := c.configureBucket(ctx, c.cluster); err != nil {
		return nil, errwrap.Wrapf("error in Connection: {{err}}", err)
	}

	return c.cluster, nil
}

func (c *couchbaseDBConnectionProducer) StaticConnection(ctx context.Context, username, password string) (interface{}, error) {
	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	var cluster *gocb.Cluster
	if clusterRaw, ok := c.staticAccountsCache.Get(username); ok {
		cluster = clusterRaw.(*gocb.Cluster)
	}
	if cluster != nil {
		return cluster, nil
	}

	// TODO repeated code can be consolidated further
	// Attempt to make a connection for this user if it does not exist
	sec, err := c.getSecurityConfig()
	if err != nil {
		return nil, err
	}

	cluster, err = gocb.Connect(
		c.Hosts,
		gocb.ClusterOptions{
			Username:       username,
			Password:       password,
			SecurityConfig: sec,
		})
	if err != nil {
		return nil, errwrap.Wrapf("error in Connection: {{err}}", err)
	}

	// TODO check if there should be different buckets for different clusters here
	if err := c.configureBucket(ctx, cluster); err != nil {
		return nil, errwrap.Wrapf("error in Connection: {{err}}", err)
	}

	c.staticAccountsCache.Add(username, cluster)
	return cluster, nil
}

func (c *couchbaseDBConnectionProducer) getSecurityConfig() (gocb.SecurityConfig, error) {
	var sec gocb.SecurityConfig
	if c.TLS {
		pem, err := base64.StdEncoding.DecodeString(c.Base64Pem)
		if err != nil {
			return gocb.SecurityConfig{}, fmt.Errorf("error decoding Base64Pem: %s", err)
		}
		rootCAs := x509.NewCertPool()
		ok := rootCAs.AppendCertsFromPEM([]byte(pem))
		if !ok {
			return gocb.SecurityConfig{}, fmt.Errorf("failed to parse root certificate")
		}
		sec = gocb.SecurityConfig{
			TLSRootCAs:    rootCAs,
			TLSSkipVerify: c.InsecureTLS,
		}
	}

	return sec, nil
}

func (c *couchbaseDBConnectionProducer) configureBucket(ctx context.Context, cluster *gocb.Cluster) error {
	var err error
	if c.BucketName != "" {
		bucket := cluster.Bucket(c.BucketName)
		// We wait until the bucket is definitely connected and setup.
		err = bucket.WaitUntilReady(computeTimeout(ctx), nil)
		if err != nil {
			return fmt.Errorf("error waiting for bucket: %s", err)
		}
	} else {
		err = cluster.WaitUntilReady(computeTimeout(ctx), nil)
		if err != nil {
			return fmt.Errorf("error waiting for cluster: %s", err)
		}
	}

	return err
}

// close terminates the database connection without locking
func (c *couchbaseDBConnectionProducer) close() error {
	if c.cluster != nil {
		if err := c.cluster.Close(&gocb.ClusterCloseOptions{}); err != nil {
			return err
		}
	}

	c.cluster = nil
	return nil
}

// Close terminates the database connection with locking
func (c *couchbaseDBConnectionProducer) Close() error {
	// Don't let anyone read or write the config while we're using it
	c.Lock()
	defer c.Unlock()

	return c.close()
}
