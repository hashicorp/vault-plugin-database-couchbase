package couchbase

import (
	"context"
	"fmt"
	docker "github.com/hashicorp/vault/helper/testhelpers/docker"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/ory/dockertest"
	dc "github.com/ory/dockertest/docker"
	"os"
	"testing"
	"time"
)

var containerInitialized bool = false
var cleanup func() = func() {}
var pre6dot5 = false // check for Pre 6.5.0 Couchbase
var adminUsername = "Administrator"
var adminPassword = "Admin123"
var bucketName = "foo"

func prepareCouchbaseTestContainer(t *testing.T) (func(), string, int) {
	if os.Getenv("COUCHBASE_HOST") != "" {
		return func() {}, os.Getenv("COUCHBASE_HOST"), 8091
	}

	if containerInitialized == true {
		return cleanup, "localhost", 8091
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	ro := &dockertest.RunOptions{
		Repository:   "docker.io/fhitchen/vault-couchbase",
		Tag:          "latest",
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

	cleanup = func() {
		docker.CleanupResource(t, pool, resource)
	}

	time.Sleep(30 * time.Second)

	containerInitialized = true

	// [TODO] wait for contaienr to be ready using sleep for now.
	//port, _ := strconv.Atoi(resource.GetPort("9042/tcp"))
	//address  := fmt.Sprintf("127.0.0.1:%d", port)

	// exponential backoff-retry
	/* if err = pool.Retry(func() error {
		clusterConfig := gocql.NewCluster(address)
		clusterConfig.Authenticator = gocql.PasswordAuthenticator{
			Username: "cassandra",
			Password: "cassandra",
		}
		clusterConfig.ProtoVersion = 4
		clusterConfig.Port = port

		session, err := clusterConfig.CreateSession()
		if err != nil {
			return errwrap.Wrapf("error creating session: {{err}}", err)
		}
		defer session.Close()
		return nil
	}); err != nil {
		cleanup()
		t.Fatalf("Could not connect to couchbase docker container: %s", err)
	}*/
	return cleanup, "0.0.0.0", 8091
}

func TestDriver(t *testing.T) {
	// Spin up couchbase
	cleanup, address, port := prepareCouchbaseTestContainer(t)

	defer cleanup()

	t.Run("Version", func(t *testing.T) { testGetCouchbaseVersion(t, address) })

	t.Run("Init", func(t *testing.T) { testCouchbaseDBInitialize_TLS(t, address, port) })
	t.Run("Init", func(t *testing.T) { testCouchbaseDBInitialize_NoTLS(t, address, port) })
	t.Run("Init", func(t *testing.T) { testCouchbaseDBInitialize_Pre6dot5TLS(t, address, port) })
	t.Run("Init", func(t *testing.T) { testCouchbaseDBInitialize_Pre6dot5NoTLS(t, address, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testCouchbaseDBCreateUser(t, address, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testCouchbaseDBCreateUser_DefaultRole(t, address, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testCouchbaseDBCreateUser_plusRole(t, address, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testCouchbaseDBCreateUser_groupOnly(t, address, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testCouchbaseDBCreateUser_roleAndGroup(t, address, port) })
	t.Run("Rotate", func(t *testing.T) { testCouchbaseDBRotateRootCredentials(t, address, port) })
	t.Run("Creds", func(t *testing.T) { testCouchbaseDBSetCredentials(t, address, port) })
	t.Run("Secret", func(t *testing.T) { testConnectionProducerSecretValues(t) })
	t.Run("TimeoutCalc", func(t *testing.T) { testComputeTimeout(t) })
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

	db := new()
	_, err = db.Init(context.Background(), connectionDetails, true)
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
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
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

	db := new()
	_, err := db.Init(context.Background(), connectionDetails, true)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	statements := dbplugin.Statements{
		Creation: []string{fmt.Sprintf(testCouchbaseRole, bucketName)},
	}

	usernameConfig := dbplugin.UsernameConfig{
		DisplayName: "test",
		RoleName:    "test",
	}

	username, password, err := db.CreateUser(context.Background(), statements, usernameConfig, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", username)
	}
}

func checkCredsExist(t *testing.T, username string, password string) error {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing checkCredsExist()")
	_, address, port := prepareCouchbaseTestContainer(t)

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

	db := new()
	_, err := db.Init(context.Background(), connectionDetails, true)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	return nil
}

func revokeUser(t *testing.T, username string) error {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing RevokeUser()")
	_, address, port := prepareCouchbaseTestContainer(t)

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
	}

	db := new()
	_, err := db.Init(context.Background(), connectionDetails, true)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	statements := dbplugin.Statements{}

	err = db.RevokeUser(context.Background(), statements, username)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return nil
}

func testCouchbaseDBCreateUser_DefaultRole(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
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

	db := new()
	_, err := db.Init(context.Background(), connectionDetails, true)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	statements := dbplugin.Statements{
		Creation: []string{},
	}

	usernameConfig := dbplugin.UsernameConfig{
		DisplayName: "test",
		RoleName:    "test",
	}

	username, password, err := db.CreateUser(context.Background(), statements, usernameConfig, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", username)
	}
}

func testCouchbaseDBCreateUser_plusRole(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing CreateUser_plusRole()")

	connectionDetails := map[string]interface{}{
		"hosts":            address,
		"port":             port,
		"username":         adminUsername,
		"password":         adminPassword,
		"protocol_version": 4,
	}

	db := new()
	_, err := db.Init(context.Background(), connectionDetails, true)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	statements := dbplugin.Statements{
		Creation: []string{fmt.Sprintf(testCouchbaseRole, bucketName)},
	}

	usernameConfig := dbplugin.UsernameConfig{
		DisplayName: "test",
		RoleName:    "test",
	}

	username, password, err := db.CreateUser(context.Background(), statements, usernameConfig, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", username)
	}
}

// g1 & g2 must exist in the database.
func testCouchbaseDBCreateUser_groupOnly(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
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

	db := new()
	_, err := db.Init(context.Background(), connectionDetails, true)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	statements := dbplugin.Statements{
		Creation: []string{testCouchbaseGroup},
	}

	usernameConfig := dbplugin.UsernameConfig{
		DisplayName: "test",
		RoleName:    "test",
	}

	username, password, err := db.CreateUser(context.Background(), statements, usernameConfig, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", username)
	}
}
func testCouchbaseDBCreateUser_roleAndGroup(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
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

	db := new()
	_, err := db.Init(context.Background(), connectionDetails, true)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	statements := dbplugin.Statements{
		Creation: []string{fmt.Sprintf(testCouchbaseRoleAndGroup, bucketName)},
	}

	usernameConfig := dbplugin.UsernameConfig{
		DisplayName: "test",
		RoleName:    "test",
	}

	username, password, err := db.CreateUser(context.Background(), statements, usernameConfig, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", username)
	}
}
func testCouchbaseDBRotateRootCredentials(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
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

	db := new()
	_, err := db.Init(context.Background(), connectionDetails, true)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	defer db.Close()

	statements := []string{""}

	password, err := db.RotateRootCredentials(context.Background(), statements)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// defer setting the password back in case the test fails.
	defer doCouchbaseDBSetCredentials(t, "rotate-root", "rotate-rootpassword", address, port)

	if err := checkCredsExist(t, db.Username, password["password"].(string)); err != nil {
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

	db := new()
	_, err := db.Init(context.Background(), connectionDetails, true)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	statements := dbplugin.Statements{}

	// test that SetCredentials fails if the user does not exist...

	staticUser := dbplugin.StaticUserConfig{
		Username: "userThatDoesNotExist",
		Password: password,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5000 * time.Millisecond)
	defer cancel()
	_, _, err = db.SetCredentials(ctx, statements, staticUser)
	if err == nil {
		t.Fatalf("err: did not error on setting password for userThatDoesNotExist")
	}

	staticUser = dbplugin.StaticUserConfig{
		Username: username,
		Password: password,
	}

	username, password, err = db.SetCredentials(context.Background(), statements, staticUser)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, username, password); err != nil {
		t.Fatalf("Could not connect with rotated credentials: %s", err)
	}
}

func testCouchbaseDBSetCredentials(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

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
	if computeTimeout(context.Background()) != 5000 * time.Millisecond {
		t.Fatalf("Background timeout not set to 5 seconds.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5000 * time.Millisecond)
	defer cancel()
	if computeTimeout(ctx) == 5000 * time.Millisecond {
		t.Fatal("WithTimeout failed")
	}
}
const testCouchbaseRole = `{"roles":[{"role":"ro_admin"},{"role":"bucket_admin","bucket_name":"%s"}]}`
const testCouchbaseGroup = `{"groups":["g1", "g2"]}`
const testCouchbaseRoleAndGroup = `{"roles":[{"role":"ro_admin"},{"role":"bucket_admin","bucket_name":"%s"}],"groups":["g1", "g2"]}`
