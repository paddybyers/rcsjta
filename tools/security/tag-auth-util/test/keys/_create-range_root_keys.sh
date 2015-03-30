#!/bin/sh
#DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
#cd $DIR

export SECRET="secret"

# remove existing keys
rm -f range* package* com*
rm -f *standalone*

# create package signer cert and key.
echo "create package signer cert and key"
echo "1 -"
keytool -genkey -keyalg RSA -alias package-signer -keystore package-signer.jks -storepass $SECRET -keypass $SECRET -dname CN=package-signer-ext -validity 360 -keysize 2048
echo "2 -"
keytool -list -keystore package-signer.jks -storepass $SECRET | grep fingerprint

# create and export range-owner root cert and key.
echo "create and export range-owner root cert and key"
echo "1 -"
keytool -genkey -keyalg RSA -alias range-root -keystore range-root.jks -storepass $SECRET -keypass $SECRET -dname CN=mcc099.mnc099 -ext 'SAN=URI:urn:urn-7:3gpp-application.ims.iari.rcs.mnc099.mcc099.*' -validity 360 -keysize 2048
echo "2 -"
keytool -importkeystore -srckeystore range-root.jks -destkeystore range-root.p12 -deststoretype PKCS12 -srcstorepass $SECRET -storepass $SECRET
echo "3 -"
openssl pkcs12 -in range-root.p12 -out range-root.pem -nodes -passin pass:$SECRET
echo "4 -"
openssl pkcs12 -in range-root.p12 -out range-root.cert -nokeys -passin pass:$SECRET
echo "5 -"
keytool -importcert -keystore range-root-truststore.jks -file range-root.cert -alias range-root -noprompt -storepass $SECRET -keypass $SECRET
echo "6 -"
keytool -importkeystore -srckeystore range-root-truststore.jks -destkeystore range-root-truststore.bks -srcstoretype JKS -deststoretype BKS -srcstorepass $SECRET -deststorepass $SECRET -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath ../../libs/bcprov-jdk15on-150.jar
#keytool -list -keystore range-root.jks -storepass $SECRET -keypass $SECRET -v

