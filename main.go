package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"os"
)

type RdsSync struct {
	adminCredentials SecretString
	session          *session.Session
	db               *sql.DB
	currentRoles     []string
	wantedRoles      []string
}

type SecretString struct {
	DbInstanceIdentifier string `json:"dbInstanceIdentifier"`
	Dbname               string `json:"dbname"`
	Engine               string `json:"engine"`
	Host                 string `json:"host"`
	Password             string `json:"password"`
	Port                 int    `json:"port"`
	Username             string `json:"username"`
}

func (r *RdsSync) initDatabase() {
	var err error
	psqlconn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=require",
		"localhost",
		r.adminCredentials.Port,
		r.adminCredentials.Username,
		r.adminCredentials.Password,
		r.adminCredentials.Dbname)

	// open database
	r.db, err = sql.Open("postgres", psqlconn)
	if err != nil {
		log.Fatal(err)
	}

	// check db
	err = r.db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	log.Info("connected to database")
}

func initRdsSync() RdsSync {
	rdsSync := RdsSync{}
	rdsSync.session = session.Must(session.NewSession())
	return rdsSync
}

func (r *RdsSync) getSecretValue(secretName string) SecretString {
	var secretString SecretString
	svc := secretsmanager.New(r.session)
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}

	result, err := svc.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeResourceNotFoundException:
				log.Fatal(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			case secretsmanager.ErrCodeInvalidParameterException:
				log.Fatal(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidRequestException:
				log.Fatal(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
			case secretsmanager.ErrCodeDecryptionFailure:
				log.Fatal(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				log.Fatal(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			default:
				log.Fatal(aerr.Error())
			}
		} else {
			log.Fatal(err.Error())
		}
		log.Fatal("something bad happened")
	}
	err = json.Unmarshal([]byte(*result.SecretString), &secretString)
	if err != nil {
		log.Fatal(err)
	}
	return secretString
}

func (r *RdsSync) getCurrentUsers() {
	query := `SELECT usename AS role_name,
		CASE
	WHEN usesuper AND usecreatedb THEN
	CAST('superuser, create database' AS pg_catalog.text)
	WHEN usesuper THEN
	CAST('superuser' AS pg_catalog.text)
	WHEN usecreatedb THEN
	CAST('create database' AS pg_catalog.text)
	ELSE
	CAST('' AS pg_catalog.text)
	END role_attributes
	FROM pg_catalog.pg_user
	ORDER BY role_name desc;`

	result := r.queryDatabase(query)
	for result.Next() {
		var role_name string
		var role_attributes string
		result.Scan(&role_name, &role_attributes)
		r.currentRoles = append(r.currentRoles, role_name)
	}
}

func (r *RdsSync) queryDatabase(query string) *sql.Rows {
	result, err := r.db.Query(query)
	if err != nil {
		log.Error(err)
	}
	return result
}

func (r *RdsSync) createUserDatabase(user string) {
	//-- drop role
	//;
	//
	//-- create role
	//
	//
	//-- change role
	//ALTER ROLE user123 WITH PASSWORD 'secret123';
	//
	//
	//-- database
	//CREATE DATABASE db123 TEMPLATE 'template0' LC_COLLATE 'C' CONNECTION LIMIT '-1' ENCODING 'utf-8';
	//
	//-- grant
	//GRANT ALL PRIVILEGES ON db123 TO user123;

	// Get password & database information from secretsmanager
	userSecret := r.getSecretValue(user)

	dropRole := "DROP ROLE IF EXISTS " + userSecret.Username
	createRole := fmt.Sprintf("CREATE USER %s WITH PASSWORD '%s'", userSecret.Username, userSecret.Password)
	createDatabase := fmt.Sprintf("CREATE DATABASE %s TEMPLATE 'template0' LC_COLLATE 'C' CONNECTION LIMIT -1 ENCODING 'utf-8';", userSecret.Dbname)
	grantAccess := fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE %s TO %s", userSecret.Dbname, userSecret.Username)

	queries := []string{dropRole, createRole, createDatabase, grantAccess}
	for _, query := range queries {
		result := r.queryDatabase(query)
		fmt.Println(result)
	}
}

func main() {
	// OS ENV Variables
	// Admin credentials --> Secretsmanager
	adminCredentials := os.Getenv("ADMIN_CREDENTIALS")
	if adminCredentials == "" {
		log.Fatal("could not find ADMIN_CREDENTIALS")
	}

	rdsSync := initRdsSync()
	rdsSync.adminCredentials = rdsSync.getSecretValue(adminCredentials)
	rdsSync.initDatabase()

	// List of roles
	// Fetches information from secrets manager based on the role name
	// Creates role to the database defined in secretsmanager
	//roles := os.Getenv("ROLES")
	//if roles == "" {
	//	log.Fatal("could not find ROLES")
	//}
	//rolesList := strings.Split(roles, ",")

	// Setup AWSCli

	//rdsSync.queryDatabase(query)
	rdsSync.getCurrentUsers()
	fmt.Println(rdsSync.currentRoles)
	rdsSync.createUserDatabase("foobar")
}
