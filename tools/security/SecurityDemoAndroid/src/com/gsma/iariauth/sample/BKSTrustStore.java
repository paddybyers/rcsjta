package com.gsma.iariauth.sample;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.gsma.iariauth.validator.dsig.CertificateInfo;
import com.gsma.iariauth.validator.dsig.TrustStore;

public class BKSTrustStore implements TrustStore {

	public BKSTrustStore(InputStream keystore) {
		String ksPasswd = "secret"; // TODO: get from provisioning
		loadKeyStore(keystore, ksPasswd);
		readKeyStore();
	}

	@Override
	public Set<TrustAnchor> getTrustAnchorsForRange(String range) {
		Set<TrustAnchor> result = null;
		List<String> rangeAliases = knownRanges.get(range);
		if(rangeAliases != null) {
			result = new HashSet<TrustAnchor>();
			for(String alias : rangeAliases) {
				try {
					result.add(new TrustAnchor((X509Certificate)ks.getCertificate(alias), null));
				} catch (KeyStoreException e) {
					e.printStackTrace();
				}
			}
		}
		return result;
	}
	
	private void loadKeyStore(InputStream keystore, String password) {
		char[] pass = password.toCharArray();
		try {
			ks = KeyStore.getInstance("bks");
			ks.load(keystore, pass);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			try {
				if (keystore != null) {
					keystore.close();
				}
			}
			catch (Throwable t) {
			}
		}
	}

	private void readKeyStore() {
		try {
			/* read all certificates and map them to ranges based on the SAN */
			Enumeration<String> aliases = ks.aliases();
			while(aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if(ks.isCertificateEntry(alias)) {
					/* this is a candidate, but we need to check that it has a SAN */
					X509Certificate cert = (X509Certificate)ks.getCertificate(alias);
					CertificateInfo certInfo = CertificateInfo.create(cert);
					if(certInfo != null) {
						String[] uriIdentities = certInfo.getURIIdentities();
						if(uriIdentities != null && uriIdentities.length > 0) {
							for(String uriIdentity : uriIdentities) {
								addAliasForRange(alias, uriIdentity);
							}
						}
					}
				}
			}
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void addAliasForRange(String alias, String range) {
		List<String> rangeAliases = knownRanges.get(range);
		if(rangeAliases == null) {
			rangeAliases = new ArrayList<String>();
			knownRanges.put(range, rangeAliases);
		}
		rangeAliases.add(alias);
	}

	private KeyStore ks;
	private final Map<String, List<String>> knownRanges = new HashMap<String, List<String>>();
}
