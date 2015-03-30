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

import com.gsma.iariauth.validator.IARIAuthDocument.AuthType;
import com.gsma.rcs.core.ims.service.extension.Extension;
import com.gsma.rcs.core.ims.service.extension.IARIUtils;
import com.gsma.rcs.core.ims.service.extension.Extension.Type;
import com.gsma.rcs.provider.LocalContentResolver;
import com.gsma.rcs.utils.logger.Logger;

import android.annotation.SuppressLint;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * SecurityLog class to manage certificates for IARI range or authorizations for IARI
 * 
 * @author yplo6403
 */
public class SecurityLog {
    /**
     * Current instance
     */
    private static volatile SecurityLog sInstance;

    private CacheAuth mCacheAuth;
    private Map<String, RevocationData> mCacheRev;

    /**
     * Content resolver
     */
    private final LocalContentResolver mLocalContentResolver;

    // certificates definition
    private static final String[] PROJ_CERTIFICATE = new String[] {
        CertificateData.KEY_CERT
    };
    private static final String CERT_WHERE_IARI_RANGE = CertificateData.KEY_IARI_RANGE.concat("=?");

    // authorizations definition
    private static final String[] AUTH_PROJ_IARI = new String[] {
        AuthorizationData.KEY_IARI
    };
    private static final String[] AUTH_PROJECTION_ID = new String[] {
        AuthorizationData.KEY_ID
    };
    private static final String[] AUTH_PROJECTION_ID_IARI = new String[] {
            AuthorizationData.KEY_ID, AuthorizationData.KEY_IARI
    };
    private static final String AUTH_WHERE_UID = new StringBuilder(AuthorizationData.KEY_PACK_UID)
            .append("=?").toString();
    private static final String AUTH_WHERE_UID_EXT_TYPE = new StringBuilder(
            AuthorizationData.KEY_PACK_UID).append("=? AND ")
            .append(AuthorizationData.KEY_EXT_TYPE).append("=?").toString();
    private static final String AUTH_WHERE_IARI = AuthorizationData.KEY_IARI.concat("=?");
    private static final String AUTH_WHERE_UID_IARI = new StringBuilder(
            AuthorizationData.KEY_PACK_UID).append("=? AND ").append(AuthorizationData.KEY_IARI)
            .append("=?").toString();

    // revocation definitions
    private static final String[] REV_PROJECTION_ID = new String[] {
        RevocationData.KEY_ID
    };
    private final String REV_WHERE_SERVICEID_CLAUSE = new StringBuilder(
            RevocationData.KEY_SERVICE_ID).append("=?").toString();

    private final static int MILLISECONDS = 1000;

    /**
     * Invalid ID
     */
    public static final int INVALID_ID = -1;

    /**
     * The logger
     */
    private static final Logger logger = Logger.getLogger(SecurityLog.class.getSimpleName());

    /**
     * Create instance
     * 
     * @param localContentResolver
     */
    public static void createInstance(LocalContentResolver localContentResolver) {
        if (sInstance != null) {
            return;

        }
        synchronized (SecurityLog.class) {
            if (sInstance == null) {
                sInstance = new SecurityLog(localContentResolver);
            }
        }
    }

    /**
     * Returns instance
     * 
     * @return Instance
     */
    public static SecurityLog getInstance() {
        return sInstance;
    }

    /**
     * Constructor
     * 
     * @param localContentResolver
     */
    private SecurityLog(LocalContentResolver localContentResolver) {
        mLocalContentResolver = localContentResolver;
        mCacheAuth = new CacheAuth();
        mCacheRev = new HashMap<String, RevocationData>();
    }

    /**
     * Add a certificate for IARI range
     * 
     * @param certificateData
     */
    public void addCertificate(CertificateData certificateData) {
        String iari = certificateData.getIARIRange();
        if (logger.isActivated()) {
            logger.debug("Add certificate for IARI range ".concat(iari));
        }
        ContentValues values = new ContentValues();
        values.put(CertificateData.KEY_IARI_RANGE, iari);
        values.put(CertificateData.KEY_CERT, certificateData.getCertificate());
        mLocalContentResolver.insert(CertificateData.CONTENT_URI, values);
    }

    /**
     * Remove a certificate for IARI range
     * 
     * @param id the row ID
     * @return The number of rows deleted.
     */
    public int removeCertificate(int id) {
        Uri uri = Uri.withAppendedPath(CertificateData.CONTENT_URI, Integer.toString(id));
        return mLocalContentResolver.delete(uri, null, null);
    }

    /**
     * Get all IARI range certificates
     * 
     * @return map which key set is the CertificateData instance and the value set is the row IDs
     */
    public Map<CertificateData, Integer> getAllCertificates() {
        Map<CertificateData, Integer> result = new HashMap<CertificateData, Integer>();
        Cursor cursor = null;
        try {
            cursor = mLocalContentResolver.query(CertificateData.CONTENT_URI, null, null, null,
                    null);
            if (!cursor.moveToFirst()) {
                return result;

            }
            int certColumnIdx = cursor.getColumnIndexOrThrow(CertificateData.KEY_CERT);
            int idColumnIdx = cursor.getColumnIndexOrThrow(CertificateData.KEY_ID);
            int iariColumnIdx = cursor.getColumnIndexOrThrow(CertificateData.KEY_IARI_RANGE);
            String cert = null;
            Integer id = null;
            String iari = null;
            do {
                cert = cursor.getString(certColumnIdx);
                id = cursor.getInt(idColumnIdx);
                iari = cursor.getString(iariColumnIdx);
                CertificateData ic = new CertificateData(iari, cert);
                result.put(ic, id);
            } while (cursor.moveToNext());
        } catch (Exception e) {
            if (logger.isActivated()) {
                logger.error("Exception occurred", e);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return result;
    }

    /**
     * Get certificates for a IARI range
     * 
     * @param iariRange
     * @return set of certificates
     */
    public Set<String> getCertificatesForIariRange(String iariRange) {
        Set<String> result = new HashSet<String>();
        Cursor cursor = null;
        try {
            cursor = mLocalContentResolver.query(CertificateData.CONTENT_URI, PROJ_CERTIFICATE,
                    CERT_WHERE_IARI_RANGE, new String[] {
                        iariRange
                    }, null);
            if (!cursor.moveToFirst()) {
                return result;

            }
            int certColumnIdx = cursor.getColumnIndexOrThrow(CertificateData.KEY_CERT);
            String cert = null;
            do {
                cert = cursor.getString(certColumnIdx);
                result.add(cert);
            } while (cursor.moveToNext());
        } catch (Exception e) {
            if (logger.isActivated()) {
                logger.error("Exception occurred", e);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return result;
    }

    /**
     * Add authorization
     * 
     * @param authData
     */
    public void addAuthorization(AuthorizationData authData) {
        boolean logActivated = logger.isActivated();
        String packageName = authData.getPackageName();
        Integer packageUid = authData.getPackageUid();
        String iari = authData.getExtension().getExtensionAsIari();

        ContentValues values = new ContentValues();
        values.put(AuthorizationData.KEY_AUTH_TYPE, authData.getAuthType().toInt());
        values.put(AuthorizationData.KEY_SIGNER, authData.getPackageSigner());
        values.put(AuthorizationData.KEY_RANGE, authData.getRange());
        values.put(AuthorizationData.KEY_IARI, iari);
        values.put(AuthorizationData.KEY_EXT_TYPE, authData.getExtension().getType().toInt());
        Integer id = getAuthorizationIdByIARI(iari);
        mCacheAuth.add(authData);
        if (INVALID_ID == id) {
            if (logActivated) {
                logger.debug(new StringBuilder("Add authorization for package '")
                        .append(packageName).append("'/").append(packageUid).append(" iari:")
                        .append(iari).toString());
            }
            values.put(AuthorizationData.KEY_PACK_NAME, packageName);
            values.put(AuthorizationData.KEY_PACK_UID, packageUid);
            mLocalContentResolver.insert(AuthorizationData.CONTENT_URI, values);
            return;

        }
        if (logActivated) {
            logger.debug(new StringBuilder("Update authorization for package '")
                    .append(packageName).append("'/").append(packageUid).append(" iari:")
                    .append(iari).toString());
        }
        Uri uri = Uri.withAppendedPath(AuthorizationData.CONTENT_URI, id.toString());
        mLocalContentResolver.update(uri, values, null, null);
    }

    /**
     * Add authorization
     * 
     * @param revocation
     */
    public void addRevocation(RevocationData revocation) {
        boolean logActivated = logger.isActivated();
        ContentValues values = new ContentValues();
        String serviceId = revocation.getServiceId();
        values.put(RevocationData.KEY_DURATION, revocation.getDuration());
        values.put(RevocationData.KEY_SERVICE_ID, serviceId);

        Integer id = getIdForRevocation(serviceId);
        mCacheRev.put(revocation.getServiceId(), revocation);
        if (INVALID_ID == id) {
            if (logActivated) {
                logger.debug("Add revocation for serviceId '".concat(serviceId));
            }
            mLocalContentResolver.insert(RevocationData.CONTENT_URI, values);
            return;
        }
        if (logActivated) {
            logger.debug("Update revocation for serviceId '".concat(serviceId));
        }
        Uri uri = Uri.withAppendedPath(RevocationData.CONTENT_URI, id.toString());
        mLocalContentResolver.update(uri, values, null, null);
    }

    /**
     * Remove a authorization
     * 
     * @param id the row ID
     * @param iari
     * @return The number of rows deleted.
     */
    public int removeAuthorization(int id, String iari) {
        mCacheAuth.remove(iari);
        Uri uri = Uri.withAppendedPath(AuthorizationData.CONTENT_URI, Integer.toString(id));
        return mLocalContentResolver.delete(uri, null, null);
    }

    /**
     * Remove a revocation
     * 
     * @param serviceId
     * @return The number of rows deleted.
     */
    public int removeRevocation(String serviceId) {
        mCacheRev.remove(serviceId);
        return mLocalContentResolver.delete(RevocationData.CONTENT_URI, REV_WHERE_SERVICEID_CLAUSE,
                new String[] {
                    serviceId
                });
    }

    /**
     * Get all authorizations
     * 
     * @return a map which key set is the AuthorizationData instance and the value set is the row
     *         IDs
     */
    public Map<AuthorizationData, Integer> getAllAuthorizations() {
        boolean logActivated = logger.isActivated();
        Map<AuthorizationData, Integer> result = new HashMap<AuthorizationData, Integer>();
        Cursor cursor = null;
        try {
            cursor = mLocalContentResolver.query(AuthorizationData.CONTENT_URI, null, null, null,
                    null);
            if (!cursor.moveToFirst()) {
                return result;

            }
            int idColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_ID);
            int packageColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_PACK_NAME);
            int iariColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_IARI);
            int extTypeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_EXT_TYPE);
            int authTypeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_AUTH_TYPE);
            int rangeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_RANGE);
            int signerColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_SIGNER);
            int packageUidColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_PACK_UID);

            String iari = null;
            Integer extType = null;
            Integer authType = null;
            String range = null;
            String packageName = null;
            String signer = null;
            Integer id = null;
            Integer packageUid = null;
            do {
                iari = cursor.getString(iariColumnIdx);
                extType = cursor.getInt(extTypeColumnIdx);
                authType = cursor.getInt(authTypeColumnIdx);
                range = cursor.getString(rangeColumnIdx);
                packageName = cursor.getString(packageColumnIdx);
                signer = cursor.getString(signerColumnIdx);
                AuthType enumAuthType = AuthType.UNSPECIFIED;
                packageUid = cursor.getInt(packageUidColumnIdx);
                try {
                    enumAuthType = AuthType.valueOf(authType);
                } catch (Exception e) {
                    if (logActivated) {
                        logger.error(
                                "Invalid authorization type:".concat(Integer.toString(authType)), e);
                    }
                }
                id = cursor.getInt(idColumnIdx);
                AuthorizationData ad = new AuthorizationData(packageUid, packageName,
                        new Extension(iari, Extension.Type.valueOf(extType)), enumAuthType, range,
                        signer);
                result.put(ad, id);
            } while (cursor.moveToNext());
        } catch (Exception e) {
            if (logActivated) {
                logger.error("Exception occurred", e);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return result;
    }

    /**
     * Get authorization by uid and extension
     * 
     * @param uid
     * @param iari
     * @return AuthorizationData or null if there is no authorization
     */
    public AuthorizationData getAuthorizationByUidAndIari(Integer uid, String iari) {
        boolean logActivated = logger.isActivated();
        AuthorizationData authorizationData = mCacheAuth.get(uid, iari);
        if (authorizationData != null) {
            return authorizationData;
        }
        Cursor cursor = null;
        try {
            cursor = mLocalContentResolver.query(AuthorizationData.CONTENT_URI, null,
                    AUTH_WHERE_UID_IARI, new String[] {
                            String.valueOf(uid), iari
                    }, null);
            if (!cursor.moveToFirst()) {
                return null;
            }
            int packageColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_PACK_NAME);
            int authTypeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_AUTH_TYPE);
            int rangeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_RANGE);
            int signerColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_SIGNER);
            int extTypeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_EXT_TYPE);

            Integer authType = cursor.getInt(authTypeColumnIdx);
            String range = cursor.getString(rangeColumnIdx);
            String packageName = cursor.getString(packageColumnIdx);
            String signer = cursor.getString(signerColumnIdx);
            AuthType enumAuthType = AuthType.UNSPECIFIED;
            try {
                enumAuthType = AuthType.valueOf(authType);
            } catch (Exception e) {
                if (logActivated) {
                    logger.error("Invalid authorization type:".concat(Integer.toString(authType)),
                            e);
                }
            }
            Integer extType = cursor.getInt(extTypeColumnIdx);
            authorizationData = new AuthorizationData(uid, packageName, new Extension(iari,
                    Extension.Type.valueOf(extType)), enumAuthType, range, signer);
            mCacheAuth.add(authorizationData);
        } catch (Exception e) {
            if (logActivated) {
                logger.error("Exception occurred", e);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return authorizationData;
    }

    /**
     * Get authorization by uid Returns an empty Set if there is no authorization for this package
     * uid
     * 
     * @param packageUid
     * @param extensionType
     * @return Set<AuthorizationData>
     */
    public Set<AuthorizationData> getAuthorizationsByUid(Integer packageUid, Type extensionType) {
        boolean logActivated = logger.isActivated();
        Set<AuthorizationData> auths = mCacheAuth.get(packageUid, extensionType);
        if (!auths.isEmpty()) {
            return auths;
        }

        Set<AuthorizationData> result = new HashSet<AuthorizationData>();
        Cursor cursor = null;
        try {
            cursor = mLocalContentResolver.query(AuthorizationData.CONTENT_URI, null,
                    AUTH_WHERE_UID_EXT_TYPE, new String[] {
                            String.valueOf(packageUid), String.valueOf(extensionType.toInt())
                    }, null);
            if (!cursor.moveToFirst()) {
                return result;

            }
            int packageColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_PACK_NAME);
            int authTypeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_AUTH_TYPE);
            int rangeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_RANGE);
            int signerColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_SIGNER);
            int iariColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_IARI);

            String range, packageName, signer, iari;
            AuthType enumAuthType = AuthType.UNSPECIFIED;
            int authType;
            do {
                authType = cursor.getInt(authTypeColumnIdx);
                range = cursor.getString(rangeColumnIdx);
                packageName = cursor.getString(packageColumnIdx);
                signer = cursor.getString(signerColumnIdx);
                iari = cursor.getString(iariColumnIdx);
                try {
                    enumAuthType = AuthType.valueOf(authType);
                } catch (Exception e) {
                    if (logActivated) {
                        logger.error(
                                "Invalid authorization type:".concat(Integer.toString(authType)), e);
                    }
                }
                result.add(new AuthorizationData(packageUid, packageName, new Extension(iari,
                        extensionType), enumAuthType, range, signer));
            } while (cursor.moveToNext());
        } catch (Exception e) {
            if (logger.isActivated()) {
                logger.error("Exception occurred", e);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return result;
    }

    /**
     * Get authorization ID for a IARI
     * 
     * @param iari
     * @return id
     */
    public Integer getAuthorizationIdByIARI(String iari) {
        Cursor cursor = null;
        try {
            cursor = mLocalContentResolver.query(AuthorizationData.CONTENT_URI, AUTH_PROJECTION_ID,
                    AUTH_WHERE_IARI, new String[] {
                        iari
                    }, null);
            if (cursor.moveToFirst()) {
                int idColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_ID);
                return cursor.getInt(idColumnIdx);
            }
        } catch (Exception e) {
            if (logger.isActivated()) {
                logger.error("Exception occurred", e);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return INVALID_ID;
    }

    /**
     * Get authorization by iari
     * 
     * @param iari
     * @return AuthorizationData or null if there is no authorization
     */
    public AuthorizationData getAuthorizationByIARI(String iari) {
        boolean logActivated = logger.isActivated();
        AuthorizationData authorizationData = mCacheAuth.get(iari);
        if (authorizationData != null) {
            return authorizationData;
        }
        Cursor cursor = null;
        try {
            cursor = mLocalContentResolver.query(AuthorizationData.CONTENT_URI, null,
                    AUTH_WHERE_IARI, new String[] {
                        iari
                    }, null);
            if (!cursor.moveToFirst()) {
                return null;
            }
            int uidColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_PACK_UID);
            int packageColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_PACK_NAME);
            int authTypeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_AUTH_TYPE);
            int rangeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_RANGE);
            int signerColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_SIGNER);
            int extTypeColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_EXT_TYPE);

            Integer uid = cursor.getInt(uidColumnIdx);
            Integer authType = cursor.getInt(authTypeColumnIdx);
            String range = cursor.getString(rangeColumnIdx);
            String packageName = cursor.getString(packageColumnIdx);
            String signer = cursor.getString(signerColumnIdx);
            AuthType enumAuthType = AuthType.UNSPECIFIED;
            try {
                enumAuthType = AuthType.valueOf(authType);
            } catch (Exception e) {
                if (logActivated) {
                    logger.error("Invalid authorization type:".concat(Integer.toString(authType)),
                            e);
                }
            }
            Integer extType = cursor.getInt(extTypeColumnIdx);
            authorizationData = new AuthorizationData(uid, packageName, new Extension(iari,
                    Extension.Type.valueOf(extType)), enumAuthType, range, signer);
            mCacheAuth.add(authorizationData);
        } catch (Exception e) {
            if (logActivated) {
                logger.error("Exception occurred", e);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return authorizationData;
    }

    /**
     * Get authorization IDs for a package UID
     * 
     * @param packageUid
     * @return Map containing id as key, and IARI as value
     */
    @SuppressLint("UseSparseArrays")
    public Map<Integer, String> getAuthorizationIdAndIARIForPackageUid(Integer packageUid) {
        Map<Integer, String> result = new HashMap<Integer, String>();
        Cursor cursor = null;
        try {
            cursor = mLocalContentResolver.query(AuthorizationData.CONTENT_URI,
                    AUTH_PROJECTION_ID_IARI, AUTH_WHERE_UID, new String[] {
                        String.valueOf(packageUid)
                    }, null);
            if (!cursor.moveToFirst()) {
                return result;

            }
            int idColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_ID);
            int extColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_IARI);
            Integer id = null;
            String extension = null;
            do {
                id = cursor.getInt(idColumnIdx);
                extension = cursor.getString(extColumnIdx);
                result.put(id, extension);
            } while (cursor.moveToNext());
        } catch (Exception e) {
            if (logger.isActivated()) {
                logger.error("Exception occurred", e);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return result;
    }

    /**
     * Get all supported extensions as serviceId
     * 
     * @return set of supported extensions
     */
    public Set<String> getSupportedExtensions() {
        Set<String> result = new HashSet<String>();
        Cursor cursor = null;
        try {
            cursor = mLocalContentResolver.query(AuthorizationData.CONTENT_URI, AUTH_PROJ_IARI,
                    null, null, null);
            if (!cursor.moveToFirst()) {
                return result;

            }
            int iariColumnIdx = cursor.getColumnIndexOrThrow(AuthorizationData.KEY_IARI);
            do {
                result.add(IARIUtils.getServiceId(cursor.getString(iariColumnIdx)));
            } while (cursor.moveToNext());
        } catch (Exception e) {
            if (logger.isActivated()) {
                logger.error("Exception occurred", e);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }

        // remove revoked extension from results
        for (Iterator<String> i = result.iterator(); i.hasNext();) {
            String serviceId = i.next();
            RevocationData revocation = getRevocationByServiceId(serviceId);
            if (revocation != null && !revocation.isAuthorized()) {
                i.remove();
            }
        }
        return result;
    }

    /**
     * Get row ID for revocation
     * 
     * @param serviceId
     * @return id or INVALID_ID if not found
     */
    public int getIdForRevocation(String serviceId) {
        Cursor cursor = null;
        try {
            cursor = mLocalContentResolver.query(RevocationData.CONTENT_URI, REV_PROJECTION_ID,
                    REV_WHERE_SERVICEID_CLAUSE, new String[] {
                        serviceId
                    }, null);
            if (cursor.moveToFirst()) {
                return cursor.getInt(cursor.getColumnIndexOrThrow(RevocationData.KEY_ID));
            }
        } catch (Exception e) {
            if (logger.isActivated()) {
                logger.error("Exception occurred", e);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return INVALID_ID;
    }

    /**
     * Get revocation by IARI
     * 
     * @param serviceId
     * @return RevocationData
     */
    public RevocationData getRevocationByServiceId(String serviceId) {
        RevocationData revocationData = mCacheRev.get(serviceId);
        if (revocationData != null) {
            return revocationData;
        }
        Cursor cursor = null;
        try {
            cursor = mLocalContentResolver.query(RevocationData.CONTENT_URI, null,
                    REV_WHERE_SERVICEID_CLAUSE, new String[] {
                        serviceId
                    }, null);
            if (!cursor.moveToFirst()) {
                return null;
            }
            int durationIdx = cursor.getColumnIndexOrThrow(RevocationData.KEY_DURATION);
            Long duration = cursor.getLong(durationIdx);
            revocationData = new RevocationData(serviceId, duration);
            mCacheRev.put(serviceId, revocationData);
            return revocationData;
        } catch (Exception e) {
            if (logger.isActivated()) {
                logger.error("Exception occurred", e);
            }
            return null;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    /**
     * Revoke an extension
     * 
     * @param iari
     * @param duration Duration in seconds
     */
    public void revokeExtension(String iari, long duration) {
        String serviceId = IARIUtils.getServiceId(iari);
        if (logger.isActivated()) {
            logger.debug("Revoke extension " + serviceId + " for " + duration + "s");
        }
        if (duration > 0) {
            duration *= MILLISECONDS;
        }
        addRevocation(new RevocationData(serviceId, duration));
    }
}
