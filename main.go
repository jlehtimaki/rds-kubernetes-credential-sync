package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
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
	log.Infof("connected to database with admin: %s", r.adminCredentials.Username)
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

func (r *RdsSync) getCurrentroles() {
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

	result, err := r.queryDatabase(query)
	if err != nil {
		log.Fatal(err.Code.Name())
	}
	for result.Next() {
		var roleName string
		var roleAttributes string
		result.Scan(&roleName, &roleAttributes)
		r.currentRoles = append(r.currentRoles, roleName)
	}
}

func (r *RdsSync) queryDatabase(query string) (*sql.Rows, *pq.Error) {
	result, err := r.db.Query(query)
	if err, ok := err.(*pq.Error); ok {
		return nil, err
	}
	return result, nil
}

func (r *RdsSync) createroleDatabase(role string) {
	// Expected error codes
	// 42710 duplicate_object
	// 42P04 duplicate_database
	allowedErrorCodes := []string{"42710", "42P04"}

	// Get password & database information from secretsmanager
	roleSecret := r.getSecretValue(role)

	//alterRole := fmt.Sprintf("ALTER ROLE %s WITH PASSWORD '%s'", roleSecret.rolename, roleSecret.Password)
	createRole := fmt.Sprintf("CREATE ROLE %s WITH LOGIN ENCRYPTED PASSWORD '%s' VALID UNTIL 'infinity';", roleSecret.Username, roleSecret.Password)
	grantRole := fmt.Sprintf("GRANT %s TO %s", role, r.adminCredentials.Username)
	createDatabase := fmt.Sprintf(
		"CREATE DATABASE %s TEMPLATE 'template0' LC_COLLATE 'C' CONNECTION LIMIT -1 ENCODING 'utf-8' OWNER %s ALLOW_CONNECTIONS true;",
		roleSecret.Dbname, roleSecret.Username)
	grantAccess := fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE %s TO %s ;", roleSecret.Dbname, roleSecret.Username)
	revokeRole := fmt.Sprintf("REVOKE %s FROM %s", role, r.adminCredentials.Username)

	queries := []string{createRole, grantRole, createDatabase, grantAccess, revokeRole}
	for _, query := range queries {
		_, err := r.queryDatabase(query)
		if err != nil {
			if contains(allowedErrorCodes, string(err.Code)) {
				log.Infof("%s for %s", err.Code.Name(), role)
				continue
			}
			log.Error(err.Code.Name())
			continue
		}
	}
}

func (r *RdsSync) dropRole(role string) {
	// Expected error codes

	// Queries
	grantRole := fmt.Sprintf("GRANT %s TO %s", role, r.adminCredentials.Username)
	reassign := fmt.Sprintf("REASSIGN OWNED BY %s TO %s", role, r.adminCredentials.Username)
	revoke := fmt.Sprintf("REVOKE ALL PRIVILEGES ON DATABASE %s FROM %s", role, role)
	revokeRole := fmt.Sprintf("REVOKE %s FROM %s", role, r.adminCredentials.Username)
	dropRole := "DROP ROLE IF EXISTS " + role
	queries := []string{grantRole, reassign, revoke, revokeRole, dropRole}

	log.Infof("dropping role %s from the database", role)

	// Loop the queries
	for _, query := range queries {
		_, err := r.queryDatabase(query)
		if err != nil {
			log.Error(err)
		}
	}

}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func main() {
	// Get Admin credentials from ENV Variable, exit if cannot be found
	adminCredentials := os.Getenv("ADMIN_CREDENTIALS")
	if adminCredentials == "" {
		log.Fatal("could not find ADMIN_CREDENTIALS")
	}

	// Init rdsSync, setting AWS Session, getting admin credentials and getting current roles from PostgreSQL
	rdsSync := initRdsSync()
	rdsSync.adminCredentials = rdsSync.getSecretValue(adminCredentials)
	rdsSync.initDatabase()
	rdsSync.getCurrentroles()

	// List of roles
	// Fetches information from secrets manager based on the role name
	// Creates role to the database defined in secretsmanager
	roles := os.Getenv("ROLES")
	if roles == "" {
		log.Fatal("could not find ROLES")
	}
	rolesList := strings.Split(roles, ",")

	// Iterate trough rolesList and if not found from currentList create the role and database
	for _, role := range rolesList {
		if !contains(rdsSync.currentRoles, role) {
			log.Infof("found new role %s, creating role and database", role)
			rdsSync.createroleDatabase(role)
		}
	}

	// Iterate through currentRoles and check if there is some role that should not be there
	for _, role := range rdsSync.currentRoles {
		if role == "rdsadmin" {
			continue
		}
		if !contains(rolesList, role) {
			rdsSync.dropRole(role)
		}
	}

	// Close the database connection
	log.Info("closing the database connection")
	rdsSync.db.Close()
}
