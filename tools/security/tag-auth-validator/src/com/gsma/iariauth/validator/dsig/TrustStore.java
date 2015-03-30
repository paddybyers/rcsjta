package com.gsma.iariauth.validator.dsig;

import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * An interface to a repository of trust anchors for signature validation.
 */
public interface TrustStore {

	/**
	 * Get the applicable trust anchors for a given IARI range
	 * @param range: the range string
	 */
	public Set<TrustAnchor> getTrustAnchorsForRange(String range);
}
