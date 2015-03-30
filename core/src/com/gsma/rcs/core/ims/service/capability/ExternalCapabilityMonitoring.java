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

package com.gsma.rcs.core.ims.service.capability;

import com.gsma.rcs.core.ims.service.extension.Extension;
import com.gsma.rcs.core.ims.service.extension.ExtensionManager;
import com.gsma.rcs.provider.settings.RcsSettings;
import com.gsma.rcs.utils.logger.Logger;
import com.gsma.services.rcs.RcsService;
import com.gsma.services.rcs.capability.CapabilityService;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Bundle;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * External capability monitoring
 * 
 * @author jexa7410
 * @author LEMORDANT Philippe
 */
public class ExternalCapabilityMonitoring extends BroadcastReceiver {

    private RcsSettings mRcsSettings;
    private ExtensionManager mExtensionManager;
    private PackageManager mPackageManager;

    /**
     * The logger
     */
    private final static Logger logger = Logger.getLogger(ExternalCapabilityMonitoring.class
            .getSimpleName());
    
    /**
     * Constructor
     * 
     * @param appContext
     * @param rcsSettings
     * @param extensionManager
     */
    public ExternalCapabilityMonitoring(Context appContext, RcsSettings rcsSettings,
            ExtensionManager extensionManager) {
        mRcsSettings = rcsSettings;
        mExtensionManager = extensionManager;
        mPackageManager = appContext.getPackageManager();
    }

    @Override
    public void onReceive(Context context, final Intent intent) {
        final boolean isLoggerActive = logger.isActivated();
        new Thread() {
            public void run() {

                try {
                    if (!mRcsSettings.isExtensionsAllowed()) {
                        if (isLoggerActive) {
                            logger.debug("Extensions are NOT allowed");
                        }
                        return;
                        // ---
                    }

                    // Get Intent parameters
                    String action = intent.getAction();
                    Integer uid = intent.getIntExtra(Intent.EXTRA_UID, -1);
                    if (uid == -1) {
                        return;
                    }

                    Uri uri = intent.getData();
                    String packageName = uri != null ? uri.getSchemeSpecificPart() : null;
                    if (packageName == null) {
                        return;
                    }

                    if (Intent.ACTION_PACKAGE_ADDED.equals(action)) {
                        // Get extensions associated to the new application
                        ApplicationInfo appInfo = mPackageManager.getApplicationInfo(packageName,
                                PackageManager.GET_META_DATA);
                        if (appInfo == null) {
                            // No app info
                            return;

                        }
                        Bundle appMeta = appInfo.metaData;
                        if (appMeta == null) {
                            // No app meta
                            return;

                        }

                        String extApplicationId = appMeta
                                .getString(RcsService.METADATA_APPLICATION_ID);
                        if (extApplicationId != null) {
                            Set<Extension> extension = new HashSet<Extension>();
                            extension.add(new Extension(extApplicationId,
                                    Extension.Type.APPLICATION_ID));
                            mExtensionManager.addSupportedExtensions(mPackageManager, uid,
                                    packageName, extension);
                        }

                        String exts = appMeta.getString(CapabilityService.INTENT_EXTENSIONS);
                        if (exts == null) {
                            // No RCS extension
                            return;

                        }

                        if (!doesPackageManageExtensions(mPackageManager, packageName)) {
                            if (isLoggerActive) {
                                logger.warn("Extensions '" + exts
                                        + "' cannot be processed for package " + packageName);
                            }
                            return;

                        }
                        if (isLoggerActive) {
                            logger.debug("Try add extensions " + exts + " for application " + uid);
                        }

                        // Add the new extension in the supported RCS extensions
                        mExtensionManager.addSupportedExtensions(mPackageManager, uid, packageName,
                                ExtensionManager.getMultimediaSessionExtensions(exts));
                        return;

                    }
                    if (Intent.ACTION_PACKAGE_REMOVED.equals(action)) {
                        if (isLoggerActive) {
                            logger.debug("Remove extensions for application " + uid + " package="
                                    + packageName);
                        }
                        // Remove the extensions in the supported RCS extensions
                        mExtensionManager.removeExtensionsForPackage(uid);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }.start();
    }

    /**
     * Check if package has activities that can be performed for the
     * CapabilityService.INTENT_EXTENSIONS intent.
     * 
     * @param pkgManager
     * @param pkgName
     * @return True if package has activities that can be performed for the
     *         CapabilityService.INTENT_EXTENSIONS intent.
     */
    public boolean doesPackageManageExtensions(PackageManager pkgManager, String pkgName) {
        // Retrieve all activities that can be performed for the CapabilityService.INTENT_EXTENSIONS
        // intent.
        Intent intent = new Intent(CapabilityService.INTENT_EXTENSIONS);
        intent.setType(ExtensionManager.ALL_EXTENSIONS_MIME_TYPE);
        List<ResolveInfo> resolveInfos = pkgManager.queryIntentActivities(intent,
                PackageManager.GET_RESOLVED_FILTER);
        for (ResolveInfo resolveInfo : resolveInfos) {
            if (pkgName.equals(resolveInfo.activityInfo.packageName)) {
                return true;
            }
        }
        return false;
    }
}
