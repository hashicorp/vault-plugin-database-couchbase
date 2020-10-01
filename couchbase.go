package couchbase

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/couchbase/gocb/v2"
	"github.com/hashicorp/errwrap"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	"github.com/hashicorp/vault/sdk/database/newdbplugin"
)

const (
	couchbaseTypeName = "couchbase"
	defaultTimeout    = 20000 * time.Millisecond
)

var (
	_ newdbplugin.Database = &CouchbaseDB{}
)

// Type that combines the custom plugins Couchbase database connection configuration options and the Vault CredentialsProducer
// used for generating user information for the Couchbase database.
type CouchbaseDB struct {
	*couchbaseDBConnectionProducer
	credsutil.CredentialsProducer
}

// Type that combines the Couchbase Roles and Groups representing specific account permissions. Used to pass roles and or
// groups between the Vault server and the custom plugin in the dbplugin.Statements
type RolesAndGroups struct {
	Roles  []gocb.Role `json:"roles"`
	Groups []string    `json:"groups"`
}

// New implements builtinplugins.BuiltinFactory
func New() (interface{}, error) {
	db := new()
	// Wrap the plugin with middleware to sanitize errors
	dbType := newdbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
	return dbType, nil
}

func new() *CouchbaseDB {
	connProducer := &couchbaseDBConnectionProducer{}
	connProducer.Type = couchbaseTypeName

	db := &CouchbaseDB{
		couchbaseDBConnectionProducer: connProducer,
	}

	return db
}

// Run instantiates a CouchbaseDB object, and runs the RPC server for the plugin
func Run() error {
	db, err := New()
	if err != nil {
		return err
	}

	newdbplugin.Serve(db.(newdbplugin.Database))

	return nil
}

func (c *CouchbaseDB) Initialize(ctx context.Context, req newdbplugin.InitializeRequest) (newdbplugin.InitializeResponse, error) {
	err := c.couchbaseDBConnectionProducer.Initialize(ctx, req.Config, req.VerifyConnection)
	if err != nil {
		return newdbplugin.InitializeResponse{}, err
	}
	resp := newdbplugin.InitializeResponse{
		Config: req.Config,
	}
	return resp, nil
}

func (c *CouchbaseDB) NewUser(ctx context.Context, req newdbplugin.NewUserRequest) (newdbplugin.NewUserResponse, error) {
	// Grab the lock
	c.Lock()
	defer c.Unlock()

	statements := removeEmpty(req.Statements.Commands)
	if len(statements) == 0 {
		return newdbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	username, err := newUsername(req.UsernameConfig)
	if err != nil {
		return newdbplugin.NewUserResponse{}, fmt.Errorf("failed to generate username: %w", err)
	}
	username = strings.ToUpper(username)

	db, err := c.getConnection(ctx)
	if err != nil {
		return newdbplugin.NewUserResponse{}, fmt.Errorf("failed to get connection: %w", err)
	}

	err = newUser(ctx, db, username, req)
	if err != nil {
		return newdbplugin.NewUserResponse{}, err
	}

	resp := newdbplugin.NewUserResponse{
		Username: username,
	}

	return resp, nil
}

func (c *CouchbaseDB) UpdateUser(ctx context.Context, req newdbplugin.UpdateUserRequest) (newdbplugin.UpdateUserResponse, error) {
	if req.Password != nil {
		err := c.changeUserPassword(ctx, req.Username, req.Password.NewPassword)
		return newdbplugin.UpdateUserResponse{}, err
	}
	return newdbplugin.UpdateUserResponse{}, nil
}

func (c *CouchbaseDB) DeleteUser(ctx context.Context, req newdbplugin.DeleteUserRequest) (newdbplugin.DeleteUserResponse, error) {
	c.Lock()
	defer c.Unlock()

	db, err := c.getConnection(ctx)
	if err != nil {
		return newdbplugin.DeleteUserResponse{}, fmt.Errorf("failed to make connection: %w", err)
	}

	// Close the database connection to ensure no new connections come in
	defer func() {
		if err := c.close(); err != nil {
			logger := hclog.New(&hclog.LoggerOptions{})
			logger.Error("defer close failed", "error", err)
		}
	}()

	// Get the UserManager
	mgr := db.Users()

	err = mgr.DropUser(req.Username, nil)

	if err != nil {
		return newdbplugin.DeleteUserResponse{}, err
	}

	return newdbplugin.DeleteUserResponse{}, nil
}

func newUser(ctx context.Context, db *gocb.Cluster, username string, req newdbplugin.NewUserRequest) error {
	jsonRoleAndGroupData := []byte(req.Statements.Commands[0])

	var rag RolesAndGroups

	err := json.Unmarshal(jsonRoleAndGroupData, &rag)
	if err != nil {
		return errwrap.Wrapf("error unmarshalling roles and groups creation statement JSON: {{err}}", err)
	}

	// Get the UserManager

	mgr := db.Users()

	user := gocb.User{
		Username:    username,
		DisplayName: req.UsernameConfig.DisplayName,
		Password:    req.Password,
		Roles:       rag.Roles,
		Groups:      rag.Groups,
	}

	err = mgr.UpsertUser(user,
		&gocb.UpsertUserOptions{
			Timeout:    computeTimeout(ctx),
			DomainName: "local",
		})
	if err != nil {
		return err
	}

	return nil
}

func newUsername(config newdbplugin.UsernameMetadata) (string, error) {
	displayName := trunc(config.DisplayName, 8)
	roleName := trunc(config.RoleName, 8)
	userUUID, err := credsutil.RandomAlphaNumeric(20, false)
	if err != nil {
		return "", err
	}

	now := fmt.Sprint(time.Now().Unix())

	parts := []string{
		"v",
		displayName,
		roleName,
		userUUID,
		now,
	}

	username := joinNonEmpty("_", parts...)
	username = trunc(username, 30)
	username = strings.Replace(username, "-", "_", -1)
	username = strings.Replace(username, ".", "_", -1)

	return username, nil
}

func (c *CouchbaseDB) changeUserPassword(ctx context.Context, username, password string) error {
	c.Lock()
	defer c.Unlock()

	db, err := c.getConnection(ctx)
	if err != nil {
		return err
	}

	// Close the database connection to ensure no new connections come in
	defer func() {
		if err := c.close(); err != nil {
			logger := hclog.New(&hclog.LoggerOptions{})
			logger.Error("defer close failed", "error", err)
		}
	}()

	// Get the UserManager
	mgr := db.Users()
	user, err := mgr.GetUser(username, nil)

	if err != nil {
		return err
	}
	user.User.Password = password

	err = mgr.UpsertUser(user.User,
		&gocb.UpsertUserOptions{
			Timeout:    computeTimeout(ctx),
			DomainName: "local",
		})

	if err != nil {
		return err
	}

	return nil
}

func removeEmpty(strs []string) []string {
	var newStrs []string
	for _, str := range strs {
		str = strings.TrimSpace(str)
		if str == "" {
			continue
		}
		newStrs = append(newStrs, str)
	}

	return newStrs
}

func trunc(str string, l int) string {
	if len(str) < l {
		return str
	}
	return str[:l]
}

func joinNonEmpty(sep string, vals ...string) string {
	if sep == "" {
		return strings.Join(vals, sep)
	}

	switch len(vals) {
	case 0:
		return ""
	case 1:
		return vals[0]
	}

	builder := &strings.Builder{}
	for _, val := range vals {
		if val == "" {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteString(sep)
		}
		builder.WriteString(val)
	}
	return builder.String()
}

func computeTimeout(ctx context.Context) (timeout time.Duration) {
	deadline, ok := ctx.Deadline()
	if ok {
		return time.Until(deadline)
	}
	return defaultTimeout
}

func (c *CouchbaseDB) getConnection(ctx context.Context) (*gocb.Cluster, error) {
	db, err := c.Connection(ctx)
	if err != nil {
		return nil, err
	}
	return db.(*gocb.Cluster), nil
}

func (c *CouchbaseDB) Type() (string, error) {
	return couchbaseTypeName, nil
}
