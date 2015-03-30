#!/bin/sh
#DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
#cd $DIR

# User parameters definition
export EXTENSION="mnc099.mcc099.messaging-range-ext1"
export EXT_FILE="_iarilist-range1.ext"
export SECRET="secret"

#internal usage
export RANGE_ROOT="range-root"

# remove existing keys
rm -f $EXTENSION*

# create entity key for specific range iari.
echo "create entity cert for specific range iari"
keytool -genkey -keyalg RSA -alias $EXTENSION -keystore $EXTENSION.jks -storepass $SECRET -keypass $SECRET -dname CN=iari.range.test -keysize 2048

# create csr for entity cert.
echo "create csr for entity cert"
keytool -certreq -keyalg RSA -alias $EXTENSION -keystore $EXTENSION.jks -storepass $SECRET -keypass $SECRET -dname CN=iari.range.test -file $EXTENSION.csr

# sign entity cert using range cert
echo "sign entity cert using range cert"
openssl x509 -req -CA $RANGE_ROOT.pem -CAkey $RANGE_ROOT.pem -in $EXTENSION.csr -out $EXTENSION.cert -days 365 -CAcreateserial -extfile $EXT_FILE

# import root cert into keystore
echo "import root cert into keystore"
keytool -importcert -keystore $EXTENSION.jks -file $RANGE_ROOT.cert -alias $RANGE_ROOT -noprompt -storepass $SECRET -keypass $SECRET

# import entity cert into keystore
echo "import entity cert into keystore"
keytool -importcert -keystore $EXTENSION.jks -file $EXTENSION.cert -alias $EXTENSION -storepass $SECRET -keypass $SECRET
