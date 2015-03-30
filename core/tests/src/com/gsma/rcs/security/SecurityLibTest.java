
package com.gsma.rcs.security;

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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import android.database.Cursor;
import android.net.Uri;
import android.test.AndroidTestCase;

import com.gsma.iariauth.validator.IARIAuthDocument.AuthType;
import com.gsma.rcs.core.ims.service.extension.Extension;
import com.gsma.rcs.provider.LocalContentResolver;
import com.gsma.rcs.provider.security.AuthorizationData;
import com.gsma.rcs.provider.security.CertificateData;
import com.gsma.rcs.provider.security.RevocationData;
import com.gsma.rcs.provider.security.SecurityLog;

public class SecurityLibTest extends AndroidTestCase {

    private final String WHERE_IARI_RANGE_CERT_CLAUSE = new StringBuilder(
            CertificateData.KEY_IARI_RANGE).append("=? AND ").append(CertificateData.KEY_CERT)
            .append("=?").toString();

    private final String[] CERT_PROJECTION_ID = new String[] {
        CertificateData.KEY_ID
    };

    private static final String[] AUTH_PROJECTION_ID = new String[] {
        AuthorizationData.KEY_ID
    };
    private static final String AUTH_WHERE_UID_IARI_CLAUSE = new StringBuilder(
            AuthorizationData.KEY_PACK_UID).append("=? AND ").append(AuthorizationData.KEY_IARI)
            .append("=?").toString();

    public static final int INVALID_ID = -1;

    /**
     * Get row ID for certificate and IARI
     * 
     * @param contentResolver
     * @param iariRangeCertificate the IARI range and associated certificate
     * @return id or INVALID_ID if not found
     */
    int getIdForIariAndCertificate(LocalContentResolver contentResolver,
            CertificateData iariRangeCertificate) {
        Cursor cursor = null;
        try {
            cursor = contentResolver.query(
                    CertificateData.CONTENT_URI,
                    CERT_PROJECTION_ID,
                    WHERE_IARI_RANGE_CERT_CLAUSE,
                    new String[] {
                            iariRangeCertificate.getIARIRange(),
                            iariRangeCertificate.getCertificate()
                    }, null);
            if (cursor.moveToFirst()) {
                return cursor.getInt(cursor.getColumnIndexOrThrow(CertificateData.KEY_ID));
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception");
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return INVALID_ID;
    }

    /**
     * Get authorization by id
     * 
     * @param contentResolver
     * @param id
     * @return AuthorizationData
     */
    public AuthorizationData getAuthorizationById(LocalContentResolver contentResolver, int id) {
        Cursor cursor = null;
        AuthorizationData authorizationData = null;
        try {
            Uri uri = Uri.withAppendedPath(AuthorizationData.CONTENT_URI, Integer.toString(id));
            cursor = contentResolver.query(uri, null, null, null, null);
            if (!cursor.moveToFirst()) {
                return null;
            }
            int packageColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_PACK_NAME);
            int iariColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_IARI);
            int authTypeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_AUTH_TYPE);
            int rangeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_RANGE);
            int signerColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_SIGNER);
            int packageUidColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_PACK_UID);
            int extTypeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_EXT_TYPE);

            String iari = cursor.getString(iariColumnIdx);
            Integer authType = cursor.getInt(authTypeColumnIdx);
            String range = cursor.getString(rangeColumnIdx);
            String packageName = cursor.getString(packageColumnIdx);
            String signer = cursor.getString(signerColumnIdx);
            AuthType enumAuthType = AuthType.UNSPECIFIED;
            Integer packageUid = cursor.getInt(packageUidColumnIdx);
            try {
                enumAuthType = AuthType.valueOf(authType);
            } catch (Exception e) {
                fail("Invalid authorization type:".concat(Integer.toString(authType)));
            }
            Integer extType = cursor.getInt(extTypeColumnIdx);
            authorizationData = new AuthorizationData(packageUid, packageName, new Extension(iari,
                    Extension.Type.valueOf(extType)), enumAuthType, range, signer);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return authorizationData;
    }

    /**
     * Get row ID for authorization
     * 
     * @param packageUid
     * @param iari
     * @return id or INVALID_ID if not found
     */
    public int getIdForPackageUidAndIari(LocalContentResolver contentResolver, Integer packageUid,
            String iari) {
        Cursor cursor = null;
        try {
            cursor = contentResolver.query(AuthorizationData.CONTENT_URI, AUTH_PROJECTION_ID,
                    AUTH_WHERE_UID_IARI_CLAUSE, new String[] {
                            String.valueOf(packageUid), iari
                    }, null);
            if (cursor.moveToFirst()) {
                return cursor.getInt(cursor.getColumnIndexOrThrow(AuthorizationData.KEY_ID));
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return INVALID_ID;
    }

    /**
     * Remove all IARI certificates
     * 
     * @param contentResolver
     * @return The number of rows deleted.
     */
    int removeAllCertificates(LocalContentResolver contentResolver) {
        return contentResolver.delete(CertificateData.CONTENT_URI, null, null);
    }

    /**
     * Remove all authorizations
     * 
     * @param contentResolver
     * @return The number of rows deleted.
     */
    void removeAllAuthorizations(LocalContentResolver contentResolver) {
        Iterator<Entry<AuthorizationData, Integer>> iter = SecurityLog.getInstance()
                .getAllAuthorizations().entrySet().iterator();
        while (iter.hasNext()) {
            Entry<AuthorizationData, Integer> entry = iter.next();
            SecurityLog.getInstance().removeAuthorization(entry.getValue(),
                    entry.getKey().getExtension().getExtensionAsIari());
        }
    }

    /**
     * Get all revocations
     * 
     * @return a map which key set is the RevocationData instance and the value set is the row IDs
     */
    public Map<RevocationData, Integer> getAllRevocations(LocalContentResolver contentResolver) {
        Map<RevocationData, Integer> result = new HashMap<RevocationData, Integer>();
        Cursor cursor = null;
        try {
            cursor = contentResolver.query(RevocationData.CONTENT_URI, null, null, null, null);
            if (!cursor.moveToFirst()) {
                return result;
            }
            int idColumnIdx = cursor.getColumnIndexOrThrow(RevocationData.KEY_ID);
            int iariColumnIdx = cursor.getColumnIndexOrThrow(RevocationData.KEY_SERVICE_ID);
            int durationColumnIdx = cursor.getColumnIndexOrThrow(RevocationData.KEY_DURATION);

            String iari = null;
            Long duration = null;
            Integer id = null;

            do {
                iari = cursor.getString(iariColumnIdx);
                duration = cursor.getLong(durationColumnIdx);
                id = cursor.getInt(idColumnIdx);
                RevocationData ad = new RevocationData(iari, duration);
                result.put(ad, id);
            } while (cursor.moveToNext());
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return result;
    }

    /**
     * Remove all Revocations
     * 
     * @param contentResolver
     * @return The number of rows deleted.
     */
    int removeAllRevocations(LocalContentResolver contentResolver) {
        return contentResolver.delete(RevocationData.CONTENT_URI, null, null);
    }

}
