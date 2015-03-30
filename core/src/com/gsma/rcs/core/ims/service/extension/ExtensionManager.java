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

import com.gsma.iariauth.validator.IARIAuthDocument;
import com.gsma.iariauth.validator.PackageProcessor;
import com.gsma.iariauth.validator.ProcessingResult;
import com.gsma.rcs.core.ims.service.capability.ExternalCapabilityMonitoring;
import com.gsma.rcs.core.ims.service.extension.Extension.Type;
import com.gsma.rcs.provider.security.AuthorizationData;
import com.gsma.rcs.provider.security.RevocationData;
import com.gsma.rcs.provider.security.SecurityLog;
import com.gsma.rcs.provider.settings.RcsSettings;
import com.gsma.rcs.provider.settings.RcsSettingsData.ExtensionPolicy;
import com.gsma.rcs.service.api.ServerPermissionDeniedException;
import com.gsma.rcs.utils.logger.Logger;
import com.gsma.services.rcs.capability.CapabilityService;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.Signature;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.text.TextUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Service extension manager which adds supported extension after having verified some authorization
 * rules.
 * 
 * @author Jean-Marc AUFFRET
 * @author P.LEMORDANT
 * @author F.ABOT
 */
public class ExtensionManager {

    private final static String LEADING_ZERO = "0";

    private final static String EXTENSION_SEPARATOR = ";";

    private final static String IARI_DOC_NAME_TYPE = ".xml";

    /**
     * Singleton of ExtensionManager
     */
    private static volatile ExtensionManager sInstance;

    private final static Logger sLogger = Logger.getLogger(ExtensionManager.class.getSimpleName());

    final private BKSTrustStore mTrustStore;

    final private RcsSettings mRcsSettings;

    final private SecurityLog mSecurityLog;

    final private Context mContext;

    private ExternalCapabilityMonitoring mCapabilityMonitoring;

    private final static Executor sUpdateSupportedExtensionProcessor = Executors
            .newSingleThreadExecutor();

    private final String mRcsFingerPrint;

    private final Map<Integer, String> mCacheFingerprint;

    /**
     * Mime type for application managing extensions
     */
    public final static String ALL_EXTENSIONS_MIME_TYPE = CapabilityService.EXTENSION_MIME_TYPE
            .concat("/*");

    /**
     * Constructor
     * 
     * @param context
     * @param rcsSettings
     * @param securityLog
     * @throws CertificateException
     * @throws NoSuchProviderException
     */
    @SuppressLint("UseSparseArrays")
    private ExtensionManager(Context context, RcsSettings rcsSettings, SecurityLog securityLog)
            throws NoSuchProviderException, CertificateException {
        try {
            mTrustStore = new BKSTrustStore(securityLog);
            mRcsSettings = rcsSettings;
            mSecurityLog = securityLog;
            mContext = context;
            mCapabilityMonitoring = new ExternalCapabilityMonitoring(mContext, mRcsSettings, this);
            mRcsFingerPrint = getFingerprint(mContext, mContext.getApplicationContext()
                    .getPackageName());
            mCacheFingerprint = new HashMap<Integer, String>();
        } catch (NoSuchProviderException e1) {
            if (sLogger.isActivated()) {
                sLogger.error("Failed to instantiate ExtensionManager", e1);
            }
            throw e1;
        } catch (CertificateException e2) {
            if (sLogger.isActivated()) {
                sLogger.error("Failed to instantiate ExtensionManager", e2);
            }
            throw e2;
        }
    }

    /**
     * Create an instance of ExtensionManager.
     *
     * @param context
     * @param rcsSettings
     * @param securityLog
     * @return the singleton instance.
     * @throws CertificateException
     * @throws NoSuchProviderException
     */
    public static ExtensionManager createInstance(Context context, RcsSettings rcsSettings,
            SecurityLog securityLog) throws NoSuchProviderException, CertificateException {
        if (sInstance != null) {
            return sInstance;
            // ---
        }
        synchronized (ExtensionManager.class) {
            if (sInstance == null) {
                sInstance = new ExtensionManager(context, rcsSettings, securityLog);
            }
        }
        return sInstance;
    }

    /**
     * Get the instance of ServiceExtensionManager.
     *
     * @return the singleton instance.
     */
    public static ExtensionManager getInstance() {
        return sInstance;
    }

    /**
     * Check if the extensions are valid.
     *
     * @param pkgManager
     * @param uid
     * @param pkgName
     * @param extensions set of extensions to validate
     * @return Set of authorization data
     */
    public Set<AuthorizationData> checkExtensions(PackageManager pkgManager, Integer uid,
            String pkgName, Set<Extension> extensions) {
        Set<AuthorizationData> result = new HashSet<AuthorizationData>();
        boolean isLogActivated = sLogger.isActivated();
        // Check each new extension
        for (Extension extension : extensions) {
            IARIAuthDocument authDocument = getExtensionAuthorizedBySecurity(pkgManager, pkgName,
                    extension.getExtensionAsServiceId());
            if (authDocument == null) {
                if (isLogActivated) {
                    sLogger.warn(new StringBuilder("Extension '")
                            .append(extension.getExtensionAsServiceId())
                            .append("' CANNOT be added: no authorized document").toString());
                }
                continue;

            }

            if (!IARIUtils.isValidIARI(authDocument.iari)) {
                if (isLogActivated) {
                    sLogger.warn(new StringBuilder("IARI '")
                            .append(authDocument.iari)
                            .append("' CANNOT be added: NOT a valid extension (not a 2nd party nor 3dr party extension)")
                            .toString());
                }
                continue;
                // ---
            }
            if (IARIUtils.isThirdPartyIARI(authDocument.iari)
                    && ExtensionPolicy.ONLY_MNO == mRcsSettings.getExtensionspolicy()) {
                if (isLogActivated) {
                    sLogger.warn(new StringBuilder("IARI '").append(authDocument.iari)
                            .append("' CANNOT be added: third party extensions are not allowed")
                            .toString());
                }
                continue;
                // ---
            }
            // Add the extension in the supported list if authorized and not yet in the list
            AuthorizationData authData = new AuthorizationData(uid, authDocument.packageName,
                    new Extension(authDocument.iari, extension.getType()), authDocument.authType,
                    authDocument.range, authDocument.packageSigner);
            result.add(authData);
            if (isLogActivated) {
                if (isLogActivated) {
                    sLogger.debug(new StringBuilder("Extension '").append(extension)
                            .append("' is authorized. IARI tag: ").append(authDocument.iari)
                            .toString());
                }
            }
        }
        return result;
    }

    /**
     * Stop monitoring for package installations and removals.
     */
    public void stop() {
        if (mCapabilityMonitoring != null) {
            mContext.unregisterReceiver(mCapabilityMonitoring);
            mCapabilityMonitoring = null;
        }
    }

    /**
     * Save authorizations in authorization table for caching
     * 
     * @param authorizationDatas collection of authorizations
     */
    private void saveAuthorizations(Collection<AuthorizationData> authorizationDatas) {
        for (AuthorizationData authData : authorizationDatas) {
            mSecurityLog.addAuthorization(authData);
        }
    }

    /**
     * Save authorizations in authorization table for caching.<br>
     * This method is used when authorization data are not controlled.
     * 
     * @param uid
     * @param pkgName
     * @param extensions set of extensions
     */
    private void saveAuthorizations(Integer uid, String pkgName, Set<Extension> extensions) {
        for (Extension extension : extensions) {
            // Save supported extension in database
            AuthorizationData authData = new AuthorizationData(uid, pkgName, extension);
            mSecurityLog.addAuthorization(authData);
        }
    }

    /**
     * Remove supported extensions for package
     *
     * @param packageUid
     */
    public void removeExtensionsForPackage(Integer packageUid) {

        // remove the fingerprint from cache
        mCacheFingerprint.remove(packageUid);

        Map<Integer, String> mapAuth = mSecurityLog
                .getAuthorizationIdAndIARIForPackageUid(packageUid);
        if (mapAuth.isEmpty()) {
            return;

        }
        if (sLogger.isActivated()) {
            sLogger.info("Remove authorizations for package uid ".concat(String.valueOf(packageUid)));
        }

        Iterator<Entry<Integer, String>> iter = mapAuth.entrySet().iterator();
        while (iter.hasNext()) {
            Entry<Integer, String> entry = iter.next();
            mSecurityLog.removeAuthorization(entry.getKey(), entry.getValue());
        }
    }

    /**
     * Add extensions if supported
     * 
     * @param pkgManager
     * @param uid
     * @param pkgName
     * @param extensions set of extensions
     */
    public void addSupportedExtensions(PackageManager pkgManager, Integer uid, String pkgName,
            Set<Extension> extensions) {
        if (!mRcsSettings.isExtensionsControlled() || isNativeApplication(uid)) {
            if (sLogger.isActivated()) {
                sLogger.debug("No control on extensions");
            }
            saveAuthorizations(uid, pkgName, extensions);
            return;
            // ---
        }
        // Check if extensions are supported
        Set<AuthorizationData> supportedExts = checkExtensions(pkgManager, uid, pkgName, extensions);
        // Save IARI Authorization document in cache to avoid having to re-process the signature
        // each time the
        // application is loaded
        saveAuthorizations(supportedExts);
    }

    /**
     * Extract set of extensions from String
     *
     * @param extensions String where extensions are concatenated with a ";" separator
     * @return the set of extensions
     */
    public static Set<String> getExtensions(String extensions) {
        Set<String> result = new HashSet<String>();
        if (TextUtils.isEmpty(extensions)) {
            return result;

        }
        String[] extensionList = extensions.split(ExtensionManager.EXTENSION_SEPARATOR);
        for (String extension : extensionList) {
            if (!TextUtils.isEmpty(extension) && extension.trim().length() > 0) {
                result.add(extension);
            }
        }
        return result;
    }

    /**
     * Extract set of extensions from String
     *
     * @param extensions String where extensions are concatenated with a ";" separator
     * @return the set of extensions
     */
    public static Set<Extension> getMultimediaSessionExtensions(String extensions) {
        Set<Extension> result = new HashSet<Extension>();
        if (TextUtils.isEmpty(extensions)) {
            return result;

        }
        String[] extensionList = extensions.split(ExtensionManager.EXTENSION_SEPARATOR);
        for (String extension : extensionList) {
            if (!TextUtils.isEmpty(extension) && extension.trim().length() > 0) {
                result.add(new Extension(extension, Extension.Type.MULTIMEDIA_SESSION));
            }
        }
        return result;
    }

    /**
     * Concatenate set of extensions into a string
     *
     * @param extensions set of extensions
     * @return String where extensions are concatenated with a ";" separator
     */
    public static String getExtensions(Set<String> extensions) {
        if (extensions == null || extensions.isEmpty()) {
            return "";

        }
        StringBuilder result = new StringBuilder();
        int size = extensions.size();
        for (String extension : extensions) {
            if (extension.trim().length() == 0) {
                --size;
                continue;

            }
            result.append(extension);
            if (--size != 0) {
                // Not last item : add separator
                result.append(EXTENSION_SEPARATOR);
            }
        }
        return result.toString();
    }

    /**
     * Get authorized extensions.<br>
     * NB: there can be at most one IARI for a given extension by app
     * 
     * @param pkgManager the app's package manager
     * @param pkgName Package name
     * @param extension Extension ID
     * @return IARIAuthDocument or null if not authorized
     */
    private IARIAuthDocument getExtensionAuthorizedBySecurity(PackageManager pkgManager,
            String pkgName, String extension) {
        boolean isLogActivated = sLogger.isActivated();
        try {
            if (isLogActivated) {
                sLogger.debug(new StringBuilder("Check extension ").append(extension)
                        .append(" for package ").append(pkgName).toString());
            }

            PackageInfo pkg = pkgManager.getPackageInfo(pkgName, PackageManager.GET_SIGNATURES);
            Signature[] signs = pkg.signatures;

            if (signs.length == 0) {
                if (isLogActivated) {
                    sLogger.debug("Extension is not authorized: no signature found");
                }
                return null;

            }
            String sha1Sign = getFingerprint(signs[0].toByteArray());
            if (isLogActivated) {
                sLogger.debug("Check application fingerprint: ".concat(sha1Sign));
            }

            PackageProcessor processor = new PackageProcessor(mTrustStore, pkgName, sha1Sign);

            // search all IARI authorizations for configuration
            // com.iari-authorization string from app pkgName

            InputStream iariDocument = getIariDocumentFromAssets(pkgManager, pkgName, extension);
            // Is IARI document resource found ?
            if (iariDocument == null) {
                if (isLogActivated) {
                    sLogger.warn("Failed to find IARI document for ".concat(extension));
                }
                return null;

            }
            if (isLogActivated) {
                sLogger.debug("IARI document found for ".concat(extension));
            }

            try {
                ProcessingResult result = processor.processIARIauthorization(iariDocument);
                if (ProcessingResult.STATUS_OK == result.getStatus()) {
                    return result.getAuthDocument();
                    // ---
                }
                if (isLogActivated) {
                    sLogger.debug(new StringBuilder("Extension '").append(extension)
                            .append("' is not authorized: ").append(result.getStatus()).append(" ")
                            .append(result.getError()).toString());
                }
            } catch (Exception e) {
                if (isLogActivated) {
                    sLogger.error("Exception raised when processing IARI doc=".concat(extension), e);
                }
                // ---
            } finally {
                iariDocument.close();
            }
        } catch (Exception e) {
            if (isLogActivated) {
                sLogger.error("Internal exception", e);
            }
        }
        return null;
    }

    /**
     * Get IARI authorization document from assets
     * 
     * @param pkgManager
     * @param pkgName
     * @param iariResourceName
     * @return InputStream or null if not found
     */
    private InputStream getIariDocumentFromAssets(PackageManager pkgManager, String pkgName,
            String iariResourceName) {
        try {
            Resources res = pkgManager.getResourcesForApplication(pkgName);
            AssetManager am = res.getAssets();
            return am.open(iariResourceName.concat(IARI_DOC_NAME_TYPE));

        } catch (IOException e) {
            if (sLogger.isActivated()) {
                sLogger.error("Cannot get IARI document from assets", e);
            }
        } catch (NameNotFoundException e) {
            if (sLogger.isActivated()) {
                sLogger.error("IARI authorization doc no found", e);
            }
        }
        return null;
    }

    /**
     * Returns the fingerprint of a certificate
     * 
     * @param cert Certificate
     * @return String as xx:yy:zz
     * @throws NoSuchAlgorithmException
     */
    private String getFingerprint(byte[] cert) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(cert);
        byte[] digest = md.digest();

        String toRet = "";
        for (int i = 0; i < digest.length; i++) {
            if (i != 0)
                toRet = toRet.concat(":");
            int b = digest[i] & 0xff;
            String hex = Integer.toHexString(b);
            if (hex.length() == 1)
                toRet = toRet.concat(LEADING_ZERO);
            toRet = toRet.concat(hex);
        }
        return toRet.toUpperCase();
    }

    /**
     * Test API permission for a packageUid and an extension type
     * 
     * @param packageUid
     * @param extensionType
     * @throws ServerPermissionDeniedException
     */
    // FGI voir exception
    public void testApiPermission(Integer packageUid, Type extensionType)
            throws ServerPermissionDeniedException {
        boolean logActivated = sLogger.isActivated();

        if (logActivated) {
            sLogger.debug("testApiPermission : packageUid : ".concat(String.valueOf(packageUid)));
        }

        if (!mRcsSettings.isExtensionsControlled()) {
            if (logActivated) {
                sLogger.debug("  --> No control on extensions");
            }
            return;
        }

        Set<AuthorizationData> authorizations = mSecurityLog.getAuthorizationsByUid(packageUid,
                extensionType);
        if (authorizations.isEmpty()) {
            if (logActivated) {
                sLogger.debug("  --> The application has no valid authorization");
            }
            throw new ServerPermissionDeniedException(new StringBuilder("Application uid '")
                    .append(packageUid).append("' is not authorized").toString());
        }

        for (AuthorizationData auth : authorizations) {
            String serviceId = auth.getExtension().getExtensionAsServiceId();
            RevocationData revocation = mSecurityLog.getRevocationByServiceId(serviceId);
            if (revocation != null && !revocation.isAuthorized()) {
                if (logActivated) {
                    sLogger.debug("  --> ServiceId is revoked : ".concat(serviceId));
                }
                throw new ServerPermissionDeniedException(new StringBuilder("Extension ")
                        .append(serviceId).append(" is not authorized").toString());
            }
        }

        if (logActivated) {
            sLogger.debug("  --> The application is authorized");
        }
    }

    /**
     * Test API permission for a packageUid and a serviceId This method should be called only for
     * multimedia session
     * 
     * @param packageUid
     * @param serviceId
     * @throws ServerPermissionDeniedException
     */
    public void testExtensionPermission(Integer packageUid, String serviceId)
            throws ServerPermissionDeniedException {
        boolean logActivated = sLogger.isActivated();

        if (logActivated) {
            sLogger.debug(new StringBuilder("testExtensionPermission : packageUid / serviceId  : ")
                    .append(packageUid).append("/").append(serviceId).toString());
        }

        if (!mRcsSettings.isExtensionsControlled()) {
            if (logActivated) {
                sLogger.debug("  --> No control on extensions");
            }
            return;
        }

        RevocationData revocation = mSecurityLog.getRevocationByServiceId(serviceId);
        if (revocation != null && !revocation.isAuthorized()) {
            if (logActivated) {
                sLogger.debug("  --> ServiceId is revoked : ".concat(serviceId));
            }
            throw new ServerPermissionDeniedException(new StringBuilder("Extension ")
                    .append(serviceId).append(" is not authorized").toString());
        }

        String iari = IARIUtils.getIARI(serviceId);
        if (mSecurityLog.getAuthorizationByUidAndIari(packageUid, iari) != null) {
            if (logActivated) {
                sLogger.debug("  --> Extension is authorized : ".concat(iari));
            }
            return;
        }

        if (logActivated) {
            sLogger.debug("    --> Extension is not authorized : ".concat(iari));
        }
        throw new ServerPermissionDeniedException(new StringBuilder("Extension ").append(serviceId)
                .append(" is not authorized").toString());
    }

    /**
     * Update supported extensions<br>
     * Updates are queued in order to be serialized.
     */
    public void updateSupportedExtensions() {
        sUpdateSupportedExtensionProcessor.execute(new SupportedExtensionUpdater(mRcsSettings,
                mSecurityLog, mContext, this, mCapabilityMonitoring));
    }

    /**
     * Returns the UID for the installed application
     * 
     * @param packageManager
     * @param packageName
     * @return
     */
    protected Integer getUidForPackage(PackageManager packageManager, String packageName) {

        try {
            return packageManager.getApplicationInfo(packageName, PackageManager.GET_META_DATA).uid;
        } catch (NameNotFoundException e) {
            if (sLogger.isActivated()) {
                sLogger.error(new StringBuilder(
                        "Package name not found in currently installed applications : ").append(
                        packageName).toString());
            }
        }
        return null;
    }

    /**
     * Return the fingerprint from the PackageManager for an application package
     * 
     * @param context
     * @param packageName
     * @return
     */
    private String getFingerprint(Context context, String packageName) {

        try {
            Signature[] sig;
            sig = mContext.getPackageManager().getPackageInfo(packageName,
                    PackageManager.GET_SIGNATURES).signatures;
            if (sig != null && sig.length > 0) {
                return getFingerprint(sig[0].toByteArray());
            }
        } catch (Exception e) {
            if (sLogger.isActivated()) {
                sLogger.error("Can not get fingerprint for Rcs application", e);
            }
        }
        return null;
    }

    /**
     * Return if the application is a "native" or "third party" application It compares client
     * application fingerprint with the RCS application fingerprint
     * 
     * @param packageUid of the application
     * @return true for native app, false otherwise
     */
    public boolean isNativeApplication(Integer packageUid) {

        if (!mCacheFingerprint.containsKey(packageUid)) {
            String[] packageNames = mContext.getPackageManager().getPackagesForUid(packageUid);
            if (packageNames != null && packageNames.length > 0) {
                String clientAppFingerprint = getFingerprint(mContext, packageNames[0]);
                mCacheFingerprint.put(packageUid, clientAppFingerprint);
            }
        }
        return mRcsFingerPrint.equals(mCacheFingerprint.get(packageUid));
    }

    /**
     * Get the Application Id (IARI) for Third party application
     * 
     * @param packageUid
     * @return applicationId or null if no control on extensions
     */
    public String getApplicationId(Integer packageUid) {

        boolean logActivated = sLogger.isActivated();
        if (!mRcsSettings.isExtensionsControlled()) {
            if (logActivated) {
                sLogger.debug("No control on applicationId");
            }
            return null;
        }

        Set<AuthorizationData> auths = mSecurityLog.getAuthorizationsByUid(packageUid,
                Extension.Type.APPLICATION_ID);
        if (auths.size() > 1) {
            if (logActivated) {
                sLogger.warn("There should be only one application identifier for third party app : uid :  "
                        .concat(String.valueOf(packageUid)));
            }
        }

        for (AuthorizationData auth : auths) {
            return auth.getExtension().getExtensionAsServiceId();
        }
        return null;
    }

}
