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

import android.net.Uri;

/**
 * A class to hold the IARI authorization data.<br>
 * It also defines data to access the authorization table from security provider.
 * 
 * @author yplo6403
 *
 */
/**
 * @author LEMORDANT Philippe
 */
public class AuthorizationData {
    /**
     * Database URI
     */
    public static final Uri CONTENT_URI = Uri
            .parse("content://com.gsma.rcs.security/authorization");

    /**
     * Column name primary key
     * <P>
     * Type: INTEGER AUTO INCREMENTED
     * </P>
     */
    public static final String KEY_ID = "_id";

    /**
     * The name of the column containing the package UID
     * <P>
     * Type: TEXT
     * </P>
     */
    public static final String KEY_PACK_UID = "pack_uid";

    /**
     * The name of the column containing the IARI tag as the unique ID of certificate
     * <P>
     * Type: TEXT
     * </P>
     */
    public static final String KEY_IARI = "iari";

    /**
     * The name of the column containing the package name.
     * <P>
     * Type: TEXT
     * </P>
     */
    public static final String KEY_PACK_NAME = "pack_name";

    /**
     * The name of the column containing the authorization type.
     * <P>
     * Type: TEXT
     * </P>
     */
    public static final String KEY_AUTH_TYPE = "auth_type";

    /**
     * The name of the column containing the package signer.
     * <P>
     * Type: TEXT
     * </P>
     */
    public static final String KEY_SIGNER = "signer";

    /**
     * The name of the column containing the IARI range.
     * <P>
     * Type: TEXT
     * </P>
     */
    public static final String KEY_RANGE = "range";

    /**
     * The name of the column containing the extension type.
     * <P>
     * Type: TEXT
     * </P>
     */
    public static final String KEY_EXT_TYPE = "ext_type";

    final private AuthType mAuthType;
    final private Integer mPackageUid;
    final private Extension mExtension;
    final private String mRange;
    final private String mPackageName;
    final private String mPackageSigner;

    /**
     * @param packageUid
     * @param packageName
     * @param extension
     * @param authType
     * @param range
     * @param packageSigner
     */
    public AuthorizationData(Integer packageUid, String packageName, Extension extension,
            AuthType authType, String range, String packageSigner) {
        mPackageUid = packageUid;
        mAuthType = authType;
        mExtension = extension;
        mRange = range;
        mPackageName = packageName;
        mPackageSigner = packageSigner;
    }

    /**
     * @param packageUid
     * @param packageName
     * @param extension
     */
    public AuthorizationData(Integer packageUid, String packageName, Extension extension) {
        mAuthType = AuthType.UNSPECIFIED;
        mPackageUid = packageUid;
        mPackageName = packageName;
        mExtension = extension;
        mPackageSigner = null;
        mRange = null;
    }

    /**
     * Gets authorization type
     * 
     * @return authType
     */
    public AuthType getAuthType() {
        return mAuthType;
    }

    /**
     * Gets extension
     * 
     * @return extension
     */
    public Extension getExtension() {
        return mExtension;
    }

    /**
     * Gets IARI range
     * 
     * @return range
     */
    public String getRange() {
        return mRange;
    }

    /**
     * Gets package name
     * 
     * @return package name
     */
    public String getPackageName() {
        return mPackageName;
    }

    /**
     * Gets package signer
     * 
     * @return package signer
     */
    public String getPackageSigner() {
        return mPackageSigner;
    }

    /**
     * Gets package UID
     * 
     * @return package UID
     */
    public Integer getPackageUid() {
        return mPackageUid;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((mAuthType == null) ? 0 : mAuthType.hashCode());
        result = prime * result + ((mExtension == null) ? 0 : mExtension.hashCode());
        result = prime * result + ((mPackageName == null) ? 0 : mPackageName.hashCode());
        result = prime * result + ((mPackageSigner == null) ? 0 : mPackageSigner.hashCode());
        result = prime * result + ((mPackageUid == null) ? 0 : mPackageUid.hashCode());
        result = prime * result + ((mRange == null) ? 0 : mRange.hashCode());
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
        AuthorizationData other = (AuthorizationData) obj;
        if (mAuthType != other.mAuthType)
            return false;
        if (mExtension == null) {
            if (other.mExtension != null)
                return false;
        } else if (!mExtension.equals(other.mExtension))
            return false;
        if (mPackageName == null) {
            if (other.mPackageName != null)
                return false;
        } else if (!mPackageName.equals(other.mPackageName))
            return false;
        if (mPackageSigner == null) {
            if (other.mPackageSigner != null)
                return false;
        } else if (!mPackageSigner.equals(other.mPackageSigner))
            return false;
        if (mPackageUid == null) {
            if (other.mPackageUid != null)
                return false;
        } else if (!mPackageUid.equals(other.mPackageUid))
            return false;
        if (mRange == null) {
            if (other.mRange != null)
                return false;
        } else if (!mRange.equals(other.mRange))
            return false;
        return true;
    }
}
