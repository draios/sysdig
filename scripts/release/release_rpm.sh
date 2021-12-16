#!/bin/bash

set -euxo pipefail

# required env variables
echo "REPOSITORY_DIR: $REPOSITORY_DIR" # root repo directory on the local filesystem
echo "RPM_BASEARCH: $RPM_BASEARCH"
echo "REPOSITORY_NAME: $REPOSITORY_NAME"
echo "PACKAGES_DIR: $PACKAGES_DIR"
echo "SCRIPTS_DIR: $SCRIPTS_DIR"
echo "S3_BUCKET: $S3_BUCKET"

mkdir -p $REPOSITORY_DIR/rpm/$RPM_BASEARCH

aws s3 sync s3://$S3_BUCKET/$REPOSITORY_NAME/rpm/$RPM_BASEARCH/ $REPOSITORY_DIR/rpm/$RPM_BASEARCH/ --exact-timestamps --acl public-read # --delete
# ls -1tdr $REPOSITORY_DIR/rpm/$RPM_BASEARCH/*sysdig*.rpm | head -n -5 | xargs -d '\n' rm -f || true

cp $PACKAGES_DIR/*rpm $REPOSITORY_DIR/rpm/$RPM_BASEARCH
createrepo $REPOSITORY_DIR/rpm/$RPM_BASEARCH

cp $SCRIPTS_DIR/draios.repo $REPOSITORY_DIR/rpm
sed -i s/_REPOSITORY_/$REPOSITORY_NAME/g $REPOSITORY_DIR/rpm/draios.repo

aws s3 cp $REPOSITORY_DIR/rpm/draios.repo s3://$S3_BUCKET/$REPOSITORY_NAME/rpm/ --acl public-read # --delete
aws s3 sync $REPOSITORY_DIR/rpm/$RPM_BASEARCH/ s3://$S3_BUCKET/$REPOSITORY_NAME/rpm/$RPM_BASEARCH/ --exact-timestamps --acl public-read --delete
