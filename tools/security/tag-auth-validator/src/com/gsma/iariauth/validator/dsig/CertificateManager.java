package com.gsma.iariauth.validator.dsig;

import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import com.gsma.iariauth.validator.IARIAuthDocument.AuthType;

/**
 * An interface representing a container of certificates
 * obtained from signature processing.
 */
public interface CertificateManager {

	/**
	 * Add a known certificate, untrusted, to the set of known certificates.
	 * This certificate may be used in constructing and validating certificate paths
	 * NOTE there is no way to add new trusted certs - this is only possible
	 * through the trustAnchor KeyStores
	 */
	public void addCert(X509Certificate cert);

	/**
	 * Retrieve certificates
	 * @return
	 */
	public List<X509Certificate> getCertificates();

	/**
	 * Add a CRL to the set of known CRLs
	 * This CRL may be used in constructing and validating certificate paths
	 */
	public void addCRL(X509CRL crl);

	/**
	 * Retrieve CRLs
	 * @return
	 */
	public List<X509CRL> getCRLs();

	/**
	 * Get trust anchors for a given range
	 */
	public Set<TrustAnchor> getTrustAnchors(AuthType authType, String range);

	/**
	 * Open a validation context
	 */
	public ValidationContext getValidationContext(AuthType authType, String range);

	/**
	 * Release resources associated with a context
	 */
	public void releaseContext(ValidationContext ctx);
}
