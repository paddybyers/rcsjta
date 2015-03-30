
package com.gsma.rcs.provider.security;

import com.gsma.rcs.core.ims.service.extension.Extension.Type;
import com.gsma.rcs.utils.logger.Logger;

import android.annotation.SuppressLint;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Cache implementation for authorization data
 */
@SuppressLint("UseSparseArrays")
public class CacheAuth {

    /**
     * The logger
     */
    private static final Logger logger = Logger.getLogger(SecurityLog.class.getSimpleName());
    private Map<String, AuthorizationData> iariMap;
    private Map<Integer, Set<AuthorizationData>> uidMap;

    /**
     * Default Constructor
     */
    public CacheAuth() {
        iariMap = new HashMap<String, AuthorizationData>();
        uidMap = new HashMap<Integer, Set<AuthorizationData>>();
    }

    /**
     * Add an authorization in the cache
     * 
     * @param authorization
     */
    public void add(AuthorizationData authorization) {
        if (logger.isActivated()) {
            logger.debug(new StringBuilder("Add authorization in cache for uid / iari : ")
                    .append(authorization.getPackageUid()).append(",")
                    .append(authorization.getExtension().getExtensionAsIari()).toString());
        }
        iariMap.put(authorization.getExtension().getExtensionAsIari(), authorization);
        Integer uid = authorization.getPackageUid();
        Set<AuthorizationData> authorizationDatas = uidMap.get(uid);
        if (authorizationDatas == null) {
            authorizationDatas = new HashSet<AuthorizationData>();
            uidMap.put(uid, authorizationDatas);
        }
        authorizationDatas.add(authorization);
    }

    /**
     * Get an authorization by IARI
     * 
     * @param iari
     * @return AuthorizationData
     */
    public AuthorizationData get(String iari) {
        if (logger.isActivated() && iariMap.get(iari) != null) {
            logger.debug("Retrieve authorization from cache for iari : ".concat(iari));
        }
        return iariMap.get(iari);
    }

    /**
     * Get an authorization by uid and iari
     * 
     * @param uid
     * @param iari
     * @return AuthorizationData
     */
    public AuthorizationData get(Integer uid, String iari) {
        AuthorizationData auth = iariMap.get(iari);
        if (auth == null) {
            return null;
        }
        if (uidMap.get(uid).contains(auth)) {
            if (logger.isActivated()) {
                logger.debug(new StringBuilder(
                        "Retrieve authorziation from cache for uid / iari : ").append(uid)
                        .append(",").append(iari).toString());
            }
            return auth;
        }
        return null;
    }

    /**
     * Get Authorizations by uid
     * 
     * @param uid
     * @param extensionType
     * @return Set<AuthorizationData>
     */
    public Set<AuthorizationData> get(Integer uid, Type extensionType) {
        Set<AuthorizationData> auths = uidMap.get(uid);
        if (auths == null) {
            return new HashSet<AuthorizationData>();
        }
        Set<AuthorizationData> matchExtensionType = new HashSet<AuthorizationData>();
        for (AuthorizationData auth : auths) {
            if (auth.getExtension().getType().equals(extensionType)) {
                matchExtensionType.add(auth);
            }
        }
        return matchExtensionType;
    }

    /**
     * Remove an authorization by iari
     * 
     * @param iari
     */
    public void remove(String iari) {
        if (logger.isActivated()) {
            logger.debug("Remove authorization in cache for iari : ".concat(iari));
        }
        AuthorizationData auth = iariMap.get(iari);
        if (auth == null) {
            return;
        }
        iariMap.remove(iari);
        uidMap.get(auth.getPackageUid()).remove(auth);
    }
};
