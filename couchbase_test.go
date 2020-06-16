package couchbase

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	docker "github.com/hashicorp/vault/helper/testhelpers/docker"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/ory/dockertest"
	dc "github.com/ory/dockertest/docker"
)

var containerInitialized bool = false
var cleanup func() = func() {}
var pre_6dot5 = false // check for Pre 6.5.0 Couchbase

func prepareCouchbaseTestContainer(t *testing.T) (func(), string, int) {
	if os.Getenv("COUCHBASE_HOST") != "" {
		return func() {}, os.Getenv("COUCHBASE_HOST"), 0
	}

	if containerInitialized == true {
		return cleanup, "localhost", 0
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
	return cleanup, "0.0.0.0", 0
}

func TestGetCouchbaseVersion(t *testing.T) {
	var err error
	pre_6dot5, err = CheckForOldCouchbaseVersion("127.0.0.1", "Administrator", "Admin123")
	if err != nil {
		t.Fatalf("Failed to detect Couchbase Version: %s", err)
	}
	log.Printf("Couchbase pre 6.5.0 is %t", pre_6dot5)
}

func testCouchbaseDB_Initialize(t *testing.T, connectionDetails map[string]interface{}) (err error) {

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
func TestCouchbaseDB_Initialize_TLS(t *testing.T) {
	log.Printf("Testing TLS Init()")

	_, address, port := prepareCouchbaseTestContainer(t)

	base64pemRootCA, err := getRootCAfromCouchbase(fmt.Sprintf("http://%s:8091/pools/default/certificate", address))
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
		"username":     "Administrator",
		"password":     "Admin123",
		"tls":          true,
		"insecure_tls": false,
		"base64pem":    base64pemRootCA,
	}
	err = testCouchbaseDB_Initialize(t, connectionDetails)
	if err != nil && pre_6dot5 {
		log.Printf("Testing TLS Init() failed as expected (no Bucket_name set)")
	}
}
func TestCouchbaseDB_Initialize_NoTLS(t *testing.T) {
	log.Printf("Testing plain text Init()")

	_, address, port := prepareCouchbaseTestContainer(t)

	address = fmt.Sprintf("couchbase://%s", "127.0.0.1")

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": "Administrator",
		"password": "Admin123",
	}
	err := testCouchbaseDB_Initialize(t, connectionDetails)

	if err != nil && pre_6dot5 {
		log.Printf("Testing TLS Init() failed as expected (no Bucket_name set)")
	}

}
func TestCouchbaseDB_Initialize_Pre6dot5TLS(t *testing.T) {
	log.Printf("Testing TLS Pre 6.5 Init()")

	_, address, port := prepareCouchbaseTestContainer(t)

	base64pemRootCA, err := getRootCAfromCouchbase(fmt.Sprintf("http://%s:8091/pools/default/certificate", address))
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
		"username":     "Administrator",
		"password":     "Admin123",
		"tls":          true,
		"insecure_tls": false,
		"base64pem":    base64pemRootCA,
		"bucket_name":  "foo",
	}
	testCouchbaseDB_Initialize(t, connectionDetails)
}
func TestCouchbaseDB_Initialize_Pre6dot5NoTLS(t *testing.T) {
	log.Printf("Testing Pre 6.5 Init()")

	_, address, port := prepareCouchbaseTestContainer(t)

	address = fmt.Sprintf("couchbase://%s", "127.0.0.1")

	connectionDetails := map[string]interface{}{
		"hosts":       address,
		"port":        port,
		"username":    "Administrator",
		"password":    "Admin123",
		"bucket_name": "foo",
	}
	testCouchbaseDB_Initialize(t, connectionDetails)
}

func TestCouchbaseDB_CreateUser(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	log.Printf("Testing CreateUser()")

	_, address, port := prepareCouchbaseTestContainer(t)

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": "Administrator",
		"password": "Admin123",
	}
	if pre_6dot5 {
		connectionDetails["bucket_name"] = "foo"
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
		Creation: []string{testCouchbaseRole},
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

	if err := testCredsExist(t, username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = testRevokeUser(t, username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", username)
	}
}

func testCredsExist(t *testing.T, username string, password string) error {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	log.Printf("Testing testCredsExist()")
	_, address, port := prepareCouchbaseTestContainer(t)

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": username,
		"password": password,
	}
	if pre_6dot5 {
		connectionDetails["bucket_name"] = "foo"
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

func testRevokeUser(t *testing.T, username string) error {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	log.Printf("Testing RevokeUser()")
	_, address, port := prepareCouchbaseTestContainer(t)

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": "Administrator",
		"password": "Admin123",
	}
	if pre_6dot5 {
		connectionDetails["bucket_name"] = "foo"
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

func TestCouchbaseDB_CreateUser_DefaultRole(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	log.Printf("Testing CreateUser_DefaultRole()")
	_, address, port := prepareCouchbaseTestContainer(t)

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": "Administrator",
		"password": "Admin123",
	}
	if pre_6dot5 {
		connectionDetails["bucket_name"] = "foo"
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

	if err := testCredsExist(t, username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = testRevokeUser(t, username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", username)
	}
}

func TestCouchbaseDB_RotateRootCredentials(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	log.Printf("Testing RotateRootCredentials()")
	_, address, port := prepareCouchbaseTestContainer(t)

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": "rotate-root",
		"password": "rotate-rootpassword",
	}
	if pre_6dot5 {
		connectionDetails["bucket_name"] = "foo"
	}

	db := new()
	_, err := db.Init(context.Background(), connectionDetails, true)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	statements := []string{""}

	password, err := db.RotateRootCredentials(context.Background(), statements)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if err := testCredsExist(t, db.Username, password["password"].(string)); err != nil {
		t.Fatalf("Could not connect with new RotatedRootcredentials: %s", err)
	}
	// Set password back
	testCouchbaseDB_SetCredentials(t, "rotate-root", "rotate-rootpassword")

	db.Close()

}

func testCouchbaseDB_SetCredentials(t *testing.T, username, password string) {

	_, address, port := prepareCouchbaseTestContainer(t)

	log.Printf("Testing SetCredentials()")

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": "Administrator",
		"password": "Admin123",
	}
	if pre_6dot5 {
		connectionDetails["bucket_name"] = "foo"
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

	_, _, err = db.SetCredentials(context.Background(), statements, staticUser)
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

	if err := testCredsExist(t, username, password); err != nil {
		t.Fatalf("Could not connect with rotated credentials: %s", err)
	}
}

func TestCouchbaseDB_SetCredentials(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	testCouchbaseDB_SetCredentials(t, "vault-edu", "password")
}

/*
func TestCouchbaseDB_StaticRole_Rotations(t *testing.T) {
	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "latest")
	defer cleanup()
	uc := userCreator(func(t *testing.T, username, password string) {
		createTestPGUser(t, connURL, username, password, testRoleStaticCreate)
	})
	testBackend_StaticRole_Rotations(t, uc, map[string]interface{}{
		"connection_url": connURL,
		"plugin_name":    "postgresql-database-plugin",
	})
}
*/
// Last test to cleanup the db
func TestCouchbaseDB_cleanup(t *testing.T) {
	cleanup()
}

const testCouchbaseRole = `[{"name":"ro_admin"},{"name":"bucket_admin","bucket":"foo"}]`
