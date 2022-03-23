# rds-secretsmanager-credential-sync (in short RSCS)

This projects goal is to sync users and create databases in secretsmanager (RDS format) to RDS instance. \
This is mainly targeted to run as a Kubernetes job but of course you can run it, however. \

> THIS PROJECT IS STILL IN EARLY POC PHASE BUT WORKS


## How to run

Program takes two ENV parameters into account

### ADMIN_CREDENTIALS
Admin credentials for RDS instance that can be found from Secrets Manager
```shell
ADMIN_CREDENTIALS=rds_admin
```

### ROLES
A list of roles/users that can be referred directly to secretsmanager names.
```shell
ROLES=rds_user1,rds_user2,rds_user3
```

## Build

### Docker
```shell
docker buildx build --platform linux/amd64,linux/arm64/v8 -t quay.io/jlehtimaki/rscs --push .
```
