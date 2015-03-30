/*******************************************************************************
 * Software Name : RCS IMS Stack
 *
 * Copyright (C) 2010 France Telecom S.A.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 ******************************************************************************/

package com.gsma.rcs.core.ims.service.extension;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import com.gsma.iariauth.validator.dsig.TrustStore;
import com.gsma.rcs.provider.security.SecurityLog;
import com.gsma.rcs.utils.logger.Logger;

/**
 * @author P.LEMORDANT
 * @author F.ABOT
 */
public class BKSTrustStore implements TrustStore {

    private CertificateFactory mFactory;

    private SecurityLog mSecurityLog;

    private final static Logger logger = Logger.getLogger(BKSTrustStore.class.getSimpleName());

    /**
     * Constructor
     * 
     * @param securityLog
     * @throws CertificateException
     * @throws NoSuchProviderException
     */
    public BKSTrustStore(SecurityLog securityLog) throws CertificateException,
            NoSuchProviderException {
        mFactory = CertificateFactory.getInstance("X.509", "BC");
        mSecurityLog = securityLog;
    }

    @Override
    public Set<TrustAnchor> getTrustAnchorsForRange(String range) {
        boolean isLoggerActivated = logger.isActivated();
        if (isLoggerActivated) {
            logger.info("Get trust anchors for range: ".concat(range));
        }
        Set<TrustAnchor> result = new HashSet<TrustAnchor>();
        Set<String> certificates = mSecurityLog.getCertificatesForIariRange(range);
        if (certificates == null || certificates.isEmpty()) {
            if (isLoggerActivated) {
                logger.warn("No certificate for IARI range: ".concat(range));
            }
            return result;

        }
        if (isLoggerActivated) {
            String nbOfMatchingEntries = Integer.toString(certificates.size());
            logger.debug(new StringBuilder(nbOfMatchingEntries)
                    .append(" certificates for IARI range: ").append(range).toString());
        }
        for (String certificate : certificates) {
            try {
                // convert String into InputStream
                InputStream is = new ByteArrayInputStream(certificate.getBytes());
                X509Certificate x509Certificate = (X509Certificate) mFactory
                        .generateCertificate(is);
                result.add(new TrustAnchor(x509Certificate, null));
            } catch (CertificateException e) {
                if (isLoggerActivated) {
                    logger.error("Cannot generate certificate", e);
                }
            }
        }
        return result;
    }

}
