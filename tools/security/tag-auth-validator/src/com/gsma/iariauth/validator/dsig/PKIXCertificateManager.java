package com.gsma.iariauth.validator.dsig;

import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.gsma.iariauth.validator.IARIAuthDocument.AuthType;

/**
 * KeySelector class that supports all of the required
 * use cases for certificate location, trust and
 * certificate path creation
 * 
 * Platform has designed trust anchors plus additional
 * known certificates
 * 
 * Supports identification of end-entity certs by KeyName
 * plus any of the standard X509Data identification means
 * 
 * Supports construction of certificate paths using
 * trust anchors, known certs, plus certs provided
 * in X509Data.
 */
public class PKIXCertificateManager implements CertificateManager {

	/**
	 * public API
	 */
	public PKIXCertificateManager(TrustStore trustStore) {
		this.trustStore = trustStore;
		//java.security.Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
	}

	/**
	 * Add a known certificate, untrusted, to the set of known certificates
	 * This certificate may be used in constructing and validating certificate paths
	 * NOTE there is no way to add new trusted certs - this is only possible
	 * through the trustAnchor KeyStores
	 */
	@Override
	public synchronized void addCert(X509Certificate cert) {
		certificates.add(cert);
	}

	/**
	 * Retrieve certificates
	 * @return
	 */
	@Override
	public synchronized List<X509Certificate> getCertificates() {
		return certificates;
	}

	/**
	 * Add a CRL to the set of known CRLs
	 * This CRL may be used in constructing and validating certificate paths
	 */
	@Override
	public synchronized void addCRL(X509CRL crl) {
		crls.add(crl);
	}

	/**
	 * Retrieve certificates
	 * @return
	 */
	@Override
	public synchronized List<X509CRL> getCRLs() {
		return crls;
	}

	@Override
	public Set<TrustAnchor> getTrustAnchors(AuthType authType, String range) {
		Set<TrustAnchor> result = null;
		if(authType == AuthType.RANGE)
			result = trustStore.getTrustAnchorsForRange(range);
		return result;
	}

	/**
	 * Get Validation Context
	 */
	@Override
	public ValidationContext getValidationContext(AuthType authType, String range) {
		PKIXValidationContext ctx = new PKIXValidationContext(this, authType, range);
		validationContexts.add(ctx);
		return ctx;
	}

	/**
	 * Release resources associated with a context
	 */
	@Override
	public void releaseContext(ValidationContext ctx) {
		if(ctx != null) {
			validationContexts.remove(ctx);
		}
	}

	private final TrustStore trustStore;
	private final List<X509Certificate> certificates = new ArrayList<X509Certificate>();
	private final List<X509CRL> crls = new ArrayList<X509CRL>();
	private final List<ValidationContext> validationContexts = new ArrayList<ValidationContext>();
}
