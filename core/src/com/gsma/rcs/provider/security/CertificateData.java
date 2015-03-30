/*******************************************************************************
 * Software Name : RCS IMS Stack
 *
 * Copyright (C) 2010 France Telecom S.A.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

package com.gsma.rcs.provider.security;

import android.net.Uri;

/**
 * A class to hold IARI range and associated certificate.<br>
 * It also defines data to access the certificate table from security provider.
 * 
 * @author F.Abot
 * @author yplo6403
 */
public class CertificateData {
    /**
     * Database URI
     */
    public static final Uri CONTENT_URI = Uri
            .parse("content://com.gsma.rcs.security/certificate");

    /**
     * Column name primary key
     * <P>
     * Type: INTEGER AUTO INCREMENTED
     * </P>
     */
    public static final String KEY_ID = "_id";

    /**
     * The name of the column containing the IARI range tag.<br>
     * A IARI range may be associated with several certificates.
     * <P>
     * Type: TEXT
     * </P>
     */
    public static final String KEY_IARI_RANGE = "iari_range";

    /**
     * The name of the column containing the certificate for the IARI document validation.
     * <P>
     * Type: TEXT
     * </P>
     */
    public static final String KEY_CERT = "cert";

    private final static int CHUNK_SIZE = 64;
    private final static String CRLF = "\r\n";

    private final static StringBuilder CERT_HEADER = new StringBuilder(
            "-----BEGIN CERTIFICATE-----").append(CRLF);
    private final static StringBuilder CERT_FOOTER = new StringBuilder("-----END CERTIFICATE-----");

    final private String mIARIRange;

    final private String mCertificate;

    /**
     * Constructor
     * 
     * @param iariRange
     * @param certificate
     */
    public CertificateData(String iariRange, String certificate) {
        mIARIRange = iariRange;
        mCertificate = certificate;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((mCertificate == null) ? 0 : mCertificate.hashCode());
        result = prime * result + ((mIARIRange == null) ? 0 : mIARIRange.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertificateData other = (CertificateData) obj;
        if (mCertificate == null) {
            if (other.mCertificate != null)
                return false;
        } else if (!mCertificate.equals(other.mCertificate))
            return false;
        if (mIARIRange == null) {
            if (other.mIARIRange != null)
                return false;
        } else if (!mIARIRange.equals(other.mIARIRange))
            return false;
        return true;
    }

    /**
     * Gets IARI range
     * 
     * @return IARI range
     */
    public String getIARIRange() {
        return mIARIRange;
    }

    /**
     * Gets certificate
     * 
     * @return certificate
     */
    public String getCertificate() {
        return mCertificate;
    }

    @Override
    public String toString() {
        return "CertificateData [IARI range=" + mIARIRange + ", cert=" + mCertificate + "]";
    }

    /**
     * Insure the certificate will be correctly formatted, including header + footer
     * 
     * @param certificate
     * @return the formatted certificate
     */
    public static String format(String certificate) {
        // remove header & footer if already here
        if (certificate.startsWith(CERT_HEADER.toString())) {
            certificate = certificate.substring(CERT_HEADER.length() - 1);
        }
        int footer = certificate.lastIndexOf(CERT_FOOTER.toString());
        if (footer >= 0) {
            certificate = certificate.substring(0, footer - 1);
        }

        // Strip space and tabs
        certificate = certificate.replaceAll("\\s+", "");

        // Append header
        StringBuilder ret = new StringBuilder(CERT_HEADER);

        int max = certificate.length();

        // add a CRLF every 64 chars chunks
        for (int i = 0; i < max; i += CHUNK_SIZE) {
            ret.append(certificate.substring(i, ((i + CHUNK_SIZE) > max) ? max : i + CHUNK_SIZE));
            ret.append(CRLF);
        }
        // finally add footer and return
        return ret.append(CERT_FOOTER).append(CRLF).toString();
    }
}
