#!/bin/bash

set -euxo pipefail

echo "REPOSITORY_DIR: $REPOSITORY_DIR"
echo "DEB_BASEARCH: $DEB_BASEARCH" # e.g. amd64
echo "REPOSITORY_NAME: $REPOSITORY_NAME"
echo "PACKAGES_DIR: $PACKAGES_DIR"
echo "SCRIPTS_DIR: $SCRIPTS_DIR"
echo "S3_BUCKET: $S3_BUCKET"
KEY_ID="$KEY_ID" # only check that it is set

DEB_REPOSITORY_DIR=$REPOSITORY_DIR/deb/

mkdir -p $REPOSITORY_DIR/deb/stable-$DEB_BASEARCH

aws s3 sync s3://$S3_BUCKET/$REPOSITORY_NAME/deb/stable-$DEB_BASEARCH/ $REPOSITORY_DIR/deb/stable-$DEB_BASEARCH/ --exact-timestamps --acl public-read # --delete
# ls -1tdr $REPOSITORY_DIR/deb/stable-$DEB_BASEARCH/*sysdig* | head -n -5 | xargs -d '\n' rm -f || true

cp $PACKAGES_DIR/*deb $REPOSITORY_DIR/deb/stable-$DEB_BASEARCH
dpkg-scanpackages --multiversion $REPOSITORY_DIR/deb/stable-$DEB_BASEARCH | sed s@$DEB_REPOSITORY_DIR@@ > $REPOSITORY_DIR/deb/stable-$DEB_BASEARCH/Packages

gzip -c $REPOSITORY_DIR/deb/stable-$DEB_BASEARCH/Packages > $REPOSITORY_DIR/deb/stable-$DEB_BASEARCH/Packages.gz
cd $REPOSITORY_DIR/deb/stable-$DEB_BASEARCH
echo "Date:" $(date -R) > Release
echo "Suite: stable-$DEB_BASEARCH" >> Release
echo "MD5Sum:" >> Release
echo -n " "$(md5sum Packages | cut -d" " -f1) >> Release
echo " "$(du -b Packages) >> Release
echo -n " "$(md5sum Packages.gz | cut -d" " -f1) >> Release
echo " "$(du -b Packages.gz) >> Release
echo "SHA1:" >> Release
echo -n " "$(sha1sum Packages | cut -d" " -f1) >> Release
echo " "$(du -b Packages) >> Release
echo -n " "$(sha1sum Packages.gz | cut -d" " -f1) >> Release
echo " "$(du -b Packages.gz) >> Release
echo "SHA256:" >> Release
echo -n " "$(sha256sum Packages | cut -d" " -f1) >> Release
echo " "$(du -b Packages) >> Release
echo -n " "$(sha256sum Packages.gz | cut -d" " -f1) >> Release
echo " "$(du -b Packages.gz) >> Release
echo "SHA512:" >> Release
echo -n " "$(sha512sum Packages | cut -d" " -f1) >> Release
echo " "$(du -b Packages) >> Release
echo -n " "$(sha512sum Packages.gz | cut -d" " -f1) >> Release
echo " "$(du -b Packages.gz) >> Release

gpg --local-user "$KEY_ID" --batch --no-tty --yes --digest-algo SHA256 -abs -o Release.gpg Release
gpg --local-user "$KEY_ID" --batch --no-tty --yes -a -s --clearsign --digest-algo SHA256 --output  InRelease Release

cd -

sed -e s/_REPOSITORY_/$REPOSITORY_NAME/g < $SCRIPTS_DIR/draios.list > $REPOSITORY_DIR/deb/draios.list

aws s3 cp $REPOSITORY_DIR/deb/draios.list s3://$S3_BUCKET/$REPOSITORY_NAME/deb/ --acl public-read
aws s3 sync $REPOSITORY_DIR/deb/stable-$DEB_BASEARCH/ s3://$S3_BUCKET/$REPOSITORY_NAME/deb/stable-$DEB_BASEARCH/ --exact-timestamps --acl public-read --delete
