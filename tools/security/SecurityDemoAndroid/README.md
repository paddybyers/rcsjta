# Tag Auth Sample

This is a trivial Android app that loads the IARIValidator and processes an IARI Authorization document.

You will need to copy the following files to the assets directory of the Android project:

    test/<iari-authorization-document>.xml
    test/keys/range-root-truststore.bks

	With:
	<iari-authorization-document> : the supported extension

The root-range.cert file must be used to set up the provisioning file.
