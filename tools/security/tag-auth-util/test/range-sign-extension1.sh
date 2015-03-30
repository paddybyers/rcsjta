#!/bin/sh
#DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
#cd $DIR

# User parameters definition
export PKG_NAME="com.gsma.iariauth.sample"
export SECRET="secret"
export EXTENSION="mnc099.mcc099.messaging-range-ext1"

# echo remove old keys etc
rm -f $EXTENSION.xml

# generate new range iari template
echo "--- create range iari template"
java -jar ../build/iaritool.jar -init -iari urn:urn-7:3gpp-application.ims.iari.rcs.$EXTENSION -range urn:urn-7:3gpp-application.ims.iari.rcs.mnc099.mcc099.* -dest $EXTENSION.xml -v

# sign package with that iari
echo "--- create iari authorization for package"
java -jar ../build/iaritool.jar -sign -template $EXTENSION.xml -dest $EXTENSION.xml -alias $EXTENSION -keystore keys/$EXTENSION.jks -storepass $SECRET -keypass $SECRET -pkgname $PKG_NAME -pkgkeystore keys/package-signer.jks -pkgalias package-signer -pkgstorepass $SECRET -v

# validate auth document
echo "--- validate signed iari authorization"
java -jar ../../tag-auth-validator/build/iarivalidator.jar -d $EXTENSION.xml -pkgname $PKG_NAME -keystore keys/range-root-truststore.jks -storepass $SECRET -pkgkeystore keys/package-signer.jks -pkgalias package-signer -pkgstorepass $SECRET -v
