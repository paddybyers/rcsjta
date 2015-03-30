/*
 * Copyright (C) 2014 GSM Association
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package com.gsma.iariauth.validator.dsig;

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

/**
 * An implementation of the TrustStore interface that uses a KeyStore as its underlying storage.
 */
public class KeystoreTrustStore implements TrustStore {

    public KeystoreTrustStore(KeyStore ks) {
        this.ks = ks;
    }

    public void load() throws KeyStoreException {
        /* read all certificates and map them to ranges based on the SAN */
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isCertificateEntry(alias)) {
                /* this is a candidate, but we need to check that it has a SAN */
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                CertificateInfo certInfo = CertificateInfo.create(cert);
                if (certInfo != null) {
                    String[] uriIdentities = certInfo.getURIIdentities();
                    if (uriIdentities != null && uriIdentities.length > 0) {
                        for (String uriIdentity : uriIdentities) {
                            addAliasForRange(alias, uriIdentity);
                        }
                    }
                }
            }
        }
    }

    @Override
    public Set<TrustAnchor> getTrustAnchorsForRange(String range) {
        Set<TrustAnchor> result = null;
        List<String> rangeAliases = knownRanges.get(range);
        if (rangeAliases != null) {
            result = new HashSet<TrustAnchor>();
            for (String alias : rangeAliases) {
                try {
                    result.add(new TrustAnchor((X509Certificate) ks.getCertificate(alias), null));
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                }
            }
        }
        return result;
    }

    private void addAliasForRange(String alias, String range) {
        List<String> rangeAliases = knownRanges.get(range);
        if (rangeAliases == null) {
            rangeAliases = new ArrayList<String>();
            knownRanges.put(range, rangeAliases);
        }
        rangeAliases.add(alias);
    }

    private final KeyStore ks;
    private final Map<String, List<String>> knownRanges = new HashMap<String, List<String>>();
}
