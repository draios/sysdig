#!/bin/bash

set -euxo pipefail

echo "REPOSITORY_DIR: $REPOSITORY_DIR"
echo "TGZ_BASEARCH: $TGZ_BASEARCH"
echo "REPOSITORY_NAME: $REPOSITORY_NAME"
echo "S3_BUCKET: $S3_BUCKET"
echo "PACKAGES_DIR: $PACKAGES_DIR"

mkdir -p $REPOSITORY_DIR/tgz/$TGZ_BASEARCH

for tgz_file in $PACKAGES_DIR/*tar.gz; do
    aws s3 cp "$tgz_file" s3://$S3_BUCKET/$REPOSITORY_NAME/tgz/$TGZ_BASEARCH/ --acl public-read
done
