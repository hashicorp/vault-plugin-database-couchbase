package couchbase

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	"github.com/ory/dockertest"
	dc "github.com/ory/dockertest/docker"
	"github.com/stretchr/testify/require"
)

var pre6dot5 = false // check for Pre 6.5.0 Couchbase

const (
	adminUsername = "Administrator"
	adminPassword = "password"
	bucketName    = "travel-sample"
)

var (
	testCouchbaseRole         = fmt.Sprintf(`{"roles":[{"role":"ro_admin"},{"role":"bucket_admin","bucket_name":"%s"}]}`, bucketName)
	testCouchbaseGroup        = `{"groups":["g1", "g2"]}`
	testCouchbaseRoleAndGroup = fmt.Sprintf(`{"roles":[{"role":"ro_admin"},{"role":"bucket_admin","bucket_name":"%s"}],"groups":["g1", "g2"]}`, bucketName)
)

func prepareCouchbaseTestContainer(t *testing.T) (func(), string, int) {
	if os.Getenv("COUCHBASE_HOST") != "" {
		return func() {}, os.Getenv("COUCHBASE_HOST"), 8091
	}
	// cbver should match a couchbase/server-sandbox docker repository tag. Default to 6.5.0
	cbver := os.Getenv("COUCHBASE_VERSION")
	if cbver == "" {
		cbver = "6.5.0"
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	ro := &dockertest.RunOptions{
		Repository:   "docker.io/couchbase/server-sandbox",
		Tag:          cbver,
		ExposedPorts: []string{"8091", "8092", "8093", "8094", "11207", "11210", "18091", "18092", "18093", "18094"},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"8091": {
				{HostIP: "0.0.0.0", HostPort: "8091"},
			},
			"8092": {
				{HostIP: "0.0.0.0", HostPort: "8092"},
			},
			"8093": {
				{HostIP: "0.0.0.0", HostPort: "8093"},
			},
			"8094": {
				{HostIP: "0.0.0.0", HostPort: "8094"},
			},
			"11207": {
				{HostIP: "0.0.0.0", HostPort: "11207"},
			},
			"11210": {
				{HostIP: "0.0.0.0", HostPort: "11210"},
			},
			"18091": {
				{HostIP: "0.0.0.0", HostPort: "18091"},
			},
			"18092": {
				{HostIP: "0.0.0.0", HostPort: "18092"},
			},
			"18093": {
				{HostIP: "0.0.0.0", HostPort: "18093"},
			},
			"18094": {
				{HostIP: "0.0.0.0", HostPort: "18094"},
			},
		},
	}
	resource, err := pool.RunWithOptions(ro)
	if err != nil {
		t.Fatalf("Could not start local couchbase docker container: %s", err)
	}

	cleanup := func() {
		err := pool.Retry(func() error {
			return pool.Purge(resource)
		})
		if err != nil {
			if strings.Contains(err.Error(), "No such container") {
				return
			}
			t.Fatalf("Failed to cleanup local container: %s", err)
		}
	}

	address := "http://127.0.0.1:8091/"

	if err = pool.Retry(func() error {
		t.Log("Waiting for the database to start...")
		resp, err := http.Get(address)
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("Got a %d status code from couchbase's Web Console", resp.StatusCode)
		}
		return nil
	}); err != nil {
		cleanup()
		t.Fatalf("Could not connect to couchbase: %s", err)
	}

	return cleanup, "0.0.0.0", 8091
}

func TestDriver(t *testing.T) {
	cleanup, address, port := prepareCouchbaseTestContainer(t)
	defer cleanup()

	err := createUser(address, port, adminUsername, adminPassword, "rotate-root", "rotate-rootpassword",
		"rotate root user", "admin")
	if err != nil {
		t.Fatalf("Failed to create rotate-root test user: %s", err)
	}
	err = createUser(address, port, adminUsername, adminPassword, "vault-edu", "password",
		"Vault education user", "admin")
	if err != nil {
		t.Fatalf("Failed to create vault-edu test user: %s", err)
	}

	t.Run("Version", func(t *testing.T) { testGetCouchbaseVersion(t, address) })

	if !pre6dot5 {
		err = createGroup(address, port, adminUsername, adminPassword, "g1", "replication_admin")
		if err != nil {
			t.Fatalf("Failed to create group g1: %s", err)
		}
		err = createGroup(address, port, adminUsername, adminPassword, "g2", "query_external_access")
		if err != nil {
			t.Fatalf("Failed to create group g1: %s", err)
		}
	} else {
		t.Log("Skipping group creation as the Couchbase DB does not support groups")
	}

	t.Run("Init", func(t *testing.T) { testCouchbaseDBInitialize_TLS(t, address, port) })
	t.Run("Init", func(t *testing.T) { testCouchbaseDBInitialize_NoTLS(t, address, port) })
	t.Run("Init", func(t *testing.T) { testCouchbaseDBInitialize_Pre6dot5TLS(t, address, port) })
	t.Run("Init", func(t *testing.T) { testCouchbaseDBInitialize_Pre6dot5NoTLS(t, address, port) })

	/* Need to pause here as sometimes the travel-sample bucket is not ready and you get strange errors like this...
		   err: {"errors":{"roles":"Cannot assign roles to user because the following roles are unknown, malformed or role
		       parameters are undefined: [bucket_admin[travel-sample]]"}}
		   the backoff function uses
	           http://Administrator:password@localhost:8091/sampleBuckets
	           to see if the couchbase container has finished installing the test bucket befor proceeding. The installed
	           element for the bucket needs to be true before proceeding.

		   [{"name":"beer-sample","installed":false,"quotaNeeded":104857600},
		    {"name":"gamesim-sample","installed":false,"quotaNeeded":104857600},
		    {"name":"travel-sample","installed":false,"quotaNeeded":104857600}] */
	waitForBucket(t, address, adminUsername, adminPassword, bucketName)

	t.Run("Create/Revoke", func(t *testing.T) { testCouchbaseDBCreateUser(t, address, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testCouchbaseDBCreateUser_DefaultRole(t, address, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testCouchbaseDBCreateUser_plusRole(t, address, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testCouchbaseDBCreateUser_groupOnly(t, address, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testCouchbaseDBCreateUser_roleAndGroup(t, address, port) })
	t.Run("Rotate", func(t *testing.T) { testCouchbaseDBRotateRootCredentials(t, address, port) })
	t.Run("Creds", func(t *testing.T) { testCouchbaseDBSetCredentials(t, address, port) })
	t.Run("Secret", func(t *testing.T) { testConnectionProducerSecretValues(t) })
	t.Run("TimeoutCalc", func(t *testing.T) { testComputeTimeout(t) })
	t.Run("Create/long username", func(t *testing.T) { testCreateuser_UsernameTemplate_LongUsername(t, address, port) })
	t.Run("Create/custom username template", func(t *testing.T) { testCreateUser_UsernameTemplate_CustomTemplate(t, address, port) })
}

func testGetCouchbaseVersion(t *testing.T, address string) {

	var err error
	pre6dot5, err = CheckForOldCouchbaseVersion(address, adminUsername, adminPassword)
	if err != nil {
		t.Fatalf("Failed to detect Couchbase Version: %s", err)
	}
	t.Logf("Couchbase pre 6.5.0 is %t", pre6dot5)
}

func setupCouchbaseDBInitialize(t *testing.T, connectionDetails map[string]interface{}) (err error) {

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err = db.Initialize(context.Background(), initReq)
	if err != nil {
		return err
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	err = db.Close()
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return nil
}
func testCouchbaseDBInitialize_TLS(t *testing.T, address string, port int) {
	t.Log("Testing TLS Init()")

	base64pemRootCA, err := getRootCAfromCouchbase(fmt.Sprintf("http://%s:%d/pools/default/certificate", address, port))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// couchbase[s] for TLS, also using insecure_tls false
	// Test will fail if we do not use 127.0.0.1 as that is the CN in the self signed server certificate
	// localhost will return an "unambiguous timeout" error. Look in the Couchbase memcached log to see the real error,
	// WARNING 43: SSL_accept() returned -1 with error 1: error:14094412:SSL routines:ssl3_read_bytes:sslv3 alert bad certificate

	address = fmt.Sprintf("couchbases://%s:%d", address, port)

	connectionDetails := map[string]interface{}{
		"hosts":        address,
		"port":         port,
		"username":     adminUsername,
		"password":     adminPassword,
		"tls":          true,
		"insecure_tls": false,
		"base64pem":    base64pemRootCA,
	}
	err = setupCouchbaseDBInitialize(t, connectionDetails)
	if err != nil && pre6dot5 {
		t.Log("Testing TLS Init() failed as expected (no BucketName set)")
	}
}
func testCouchbaseDBInitialize_NoTLS(t *testing.T, address string, port int) {
	t.Log("Testing plain text Init()")

	address = fmt.Sprintf("couchbase://%s:%d", address, port)

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}
	err := setupCouchbaseDBInitialize(t, connectionDetails)

	if err != nil && pre6dot5 {
		t.Log("Testing TLS Init() failed as expected (no BucketName set)")
	}

}
func testCouchbaseDBInitialize_Pre6dot5TLS(t *testing.T, address string, port int) {
	t.Log("Testing TLS Pre 6.5 Init()")

	base64pemRootCA, err := getRootCAfromCouchbase(fmt.Sprintf("http://%s:%d/pools/default/certificate", address, port))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// couchbase[s] for TLS, also using insecure_tls false
	// Test will fail if we do not use 127.0.0.1 as that is the CN in the self signed server certificate
	// localhost will return an "unambiguous timeout" error. Look in the Couchbase memcached log to see the real error,
	// WARNING 43: SSL_accept() returned -1 with error 1: error:14094412:SSL routines:ssl3_read_bytes:sslv3 alert bad certificate

	address = fmt.Sprintf("couchbases://%s", "127.0.0.1")

	connectionDetails := map[string]interface{}{
		"hosts":        address,
		"port":         port,
		"username":     adminUsername,
		"password":     adminPassword,
		"tls":          true,
		"insecure_tls": false,
		"base64pem":    base64pemRootCA,
		"bucket_name":  bucketName,
	}
	setupCouchbaseDBInitialize(t, connectionDetails)
}
func testCouchbaseDBInitialize_Pre6dot5NoTLS(t *testing.T, address string, port int) {
	t.Log("Testing Pre 6.5 Init()")

	address = fmt.Sprintf("couchbase://%s:%d", address, port)

	connectionDetails := map[string]interface{}{
		"hosts":       address,
		"port":        port,
		"username":    adminUsername,
		"password":    adminPassword,
		"bucket_name": bucketName,
	}
	setupCouchbaseDBInitialize(t, connectionDetails)
}

func testCouchbaseDBCreateUser(t *testing.T, address string, port int) {
	t.Log("Testing CreateUser()")

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("Failed to initialize database: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{testCouchbaseRole},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

func checkCredsExist(t *testing.T, username, password, address string, port int) error {
	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": username,
		"password": password,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
	}

	time.Sleep(1 * time.Second) // a brief pause to let couchbase finish creating the account

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	return nil
}

func revokeUser(t *testing.T, username, address string, port int) error {
	t.Log("Testing RevokeUser()")

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	delUserReq := dbplugin.DeleteUserRequest{Username: username}

	_, err = db.DeleteUser(context.Background(), delUserReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return nil
}

func testCouchbaseDBCreateUser_DefaultRole(t *testing.T, address string, port int) {
	t.Log("Testing CreateUser_DefaultRole()")

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	username := "test"
	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: username,
			RoleName:    username,
		},
		Statements: dbplugin.Statements{
			Commands: []string{},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", username)
	}

	db.Close()
}

func testCouchbaseDBCreateUser_plusRole(t *testing.T, address string, port int) {
	t.Log("Testing CreateUser_plusRole()")

	connectionDetails := map[string]interface{}{
		"hosts":            address,
		"port":             port,
		"username":         adminUsername,
		"password":         adminPassword,
		"protocol_version": 4,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{testCouchbaseRole},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

// g1 & g2 must exist in the database.
func testCouchbaseDBCreateUser_groupOnly(t *testing.T, address string, port int) {
	if pre6dot5 {
		t.Log("Skipping as groups are not supported pre6.5.0")
		t.SkipNow()
	}
	t.Log("Testing CreateUser_groupOnly()")

	connectionDetails := map[string]interface{}{
		"hosts":            address,
		"port":             port,
		"username":         adminUsername,
		"password":         adminPassword,
		"protocol_version": 4,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{fmt.Sprintf(testCouchbaseGroup)},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}
func testCouchbaseDBCreateUser_roleAndGroup(t *testing.T, address string, port int) {
	if pre6dot5 {
		t.Log("Skipping as groups are not supported pre6.5.0")
		t.SkipNow()
	}
	t.Log("Testing CreateUser_roleAndGroup()")

	connectionDetails := map[string]interface{}{
		"hosts":            address,
		"port":             port,
		"username":         adminUsername,
		"password":         adminPassword,
		"protocol_version": 4,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{testCouchbaseRoleAndGroup},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}
func testCouchbaseDBRotateRootCredentials(t *testing.T, address string, port int) {
	t.Log("Testing RotateRootCredentials()")

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": "rotate-root",
		"password": "rotate-rootpassword",
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	defer db.Close()

	updateReq := dbplugin.UpdateUserRequest{
		Username: "rotate-root",
		Password: &dbplugin.ChangePassword{
			NewPassword: "newpassword",
		},
	}

	_, err = db.UpdateUser(context.Background(), updateReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// defer setting the password back in case the test fails.
	defer doCouchbaseDBSetCredentials(t, "rotate-root", "rotate-rootpassword", address, port)

	if err := checkCredsExist(t, db.Username, "newpassword", address, port); err != nil {
		t.Fatalf("Could not connect with new RotatedRootcredentials: %s", err)
	}
}

func doCouchbaseDBSetCredentials(t *testing.T, username, password, address string, port int) {

	t.Log("Testing SetCredentials()")

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	// test that SetCredentials fails if the user does not exist...
	updateReq := dbplugin.UpdateUserRequest{
		Username: "userThatDoesNotExist",
		Password: &dbplugin.ChangePassword{
			NewPassword: "goodPassword",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5000*time.Millisecond)
	defer cancel()
	_, err = db.UpdateUser(ctx, updateReq)
	if err == nil {
		t.Fatalf("err: did not error on setting password for userThatDoesNotExist")
	}

	updateReq = dbplugin.UpdateUserRequest{
		Username: username,
		Password: &dbplugin.ChangePassword{
			NewPassword: password,
		},
	}

	_, err = db.UpdateUser(context.Background(), updateReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, username, password, address, port); err != nil {
		t.Fatalf("Could not connect with rotated credentials: %s", err)
	}
}

func testCouchbaseDBSetCredentials(t *testing.T, address string, port int) {
	doCouchbaseDBSetCredentials(t, "vault-edu", "password", address, port)
}

func testConnectionProducerSecretValues(t *testing.T) {
	t.Log("Testing couchbaseDBConnectionProducer.secretValues()")

	cp := &couchbaseDBConnectionProducer{
		Username: "USR",
		Password: "PWD",
	}

	if cp.secretValues()["USR"] != "[username]" &&
		cp.secretValues()["PWD"] != "[password]" {
		t.Fatal("couchbaseDBConnectionProducer.secretValues() test failed.")
	}
}

func testComputeTimeout(t *testing.T) {
	t.Log("Testing computeTimeout")
	if computeTimeout(context.Background()) != defaultTimeout {
		t.Fatalf("Background timeout not set to %s milliseconds.", defaultTimeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	if computeTimeout(ctx) == defaultTimeout {
		t.Fatal("WithTimeout failed")
	}
}

func testCreateUser_UsernameTemplate_CustomTemplate(t *testing.T, address string, port int) {
	bucket := ""
	if pre6dot5 {
		bucket = bucketName
	}
	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"hosts":             address,
			"port":              port,
			"username":          adminUsername,
			"password":          adminPassword,
			"bucket_name":       bucket,
			"username_template": "{{random 2 | uppercase}}_{{unix_time}}_{{.RoleName | uppercase}}_{{.DisplayName | uppercase}}",
		},
		VerifyConnection: true,
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	dbtesting.AssertInitialize(t, db, initReq)

	password := "98yq3thgnakjsfhjkl"
	newUserReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "token",
			RoleName:    "testrolenamewithmanycharacters",
		},
		Statements: dbplugin.Statements{
			Commands: []string{testCouchbaseRole},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	expectedUsernameRegex := "^[A-Z0-9]{2}_[0-9]{10}_TESTROLENAMEWITHMANYCHARACTERS_TOKEN$"

	newUserResp, err := db.NewUser(context.Background(), newUserReq)
	require.NoError(t, err)
	require.Regexp(t, expectedUsernameRegex, newUserResp.Username)

	if err := checkCredsExist(t, newUserResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect to database: %s", err)
	}
}

func testCreateuser_UsernameTemplate_LongUsername(t *testing.T, address string, port int) {
	bucket := ""
	if pre6dot5 {
		bucket = bucketName
	}
	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"hosts":       address,
			"port":        port,
			"username":    adminUsername,
			"password":    adminPassword,
			"bucket_name": bucket,
		},
		VerifyConnection: true,
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	dbtesting.AssertInitialize(t, db, initReq)

	password := "98yq3thgnakjsfhjkl"
	newUserReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "thisissomereallylongdisplaynameforthetemplate123456789012345678901234567890",
			RoleName:    "thisissomereallylongrolenameforthetemplate123456789012345678901234567890",
		},
		Statements: dbplugin.Statements{
			Commands: []string{testCouchbaseRole},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	// Ensure that we're within the hard cap by couchbase on the default template
	expectedUsernameRegex := `^.{128}$`

	newUserResp, err := db.NewUser(context.Background(), newUserReq)
	require.NoError(t, err)
	require.Regexp(t, expectedUsernameRegex, newUserResp.Username)

	if err := checkCredsExist(t, newUserResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect to database: %s", err)
	}
}
