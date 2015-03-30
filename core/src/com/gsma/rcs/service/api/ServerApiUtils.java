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

package com.gsma.rcs.service.api;

import com.gsma.rcs.core.Core;
import com.gsma.rcs.core.ims.network.ImsNetworkInterface;
import com.gsma.rcs.core.ims.network.sip.FeatureTags;
import com.gsma.rcs.core.ims.service.ImsServiceSession;
import com.gsma.rcs.core.ims.service.extension.Extension;
import com.gsma.rcs.core.ims.service.extension.ExtensionManager;
import com.gsma.rcs.core.ims.service.im.chat.OriginatingOneToOneChatSession;
import com.gsma.rcs.provider.security.RevocationData;
import com.gsma.rcs.utils.logger.Logger;
import com.gsma.services.rcs.RcsServiceRegistration;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * Server API utils
 * 
 * @author Jean-Marc AUFFRET
 */
public class ServerApiUtils {

    private final static Logger logger = Logger.getLogger(ExtensionManager.class.getSimpleName());

    /**
     * Test core
     * 
     * @throws ServerApiException
     */
    public static void testCore() throws ServerApiException {
        if (Core.getInstance() == null) {
            throw new ServerApiException("Core is not instanciated");
        }
    }

    /**
     * Test IMS connection
     * 
     * @throws ServerApiException
     */
    public static void testIms() throws ServerApiException {
        if (!isImsConnected()) {
            throw new ServerApiException("Core is not connected to IMS");
        }
    }

    /**
     * Is connected to IMS
     * 
     * @return Boolean
     */
    public static boolean isImsConnected() {
        return ((Core.getInstance() != null)
                && (Core.getInstance().getImsModule().getCurrentNetworkInterface() != null) && (Core
                .getInstance().getImsModule().getCurrentNetworkInterface().isRegistered()));
    }

    /**
     * Gets the reason code for IMS service registration
     * 
     * @return reason code
     */
    public static RcsServiceRegistration.ReasonCode getServiceRegistrationReasonCode() {
        Core core = Core.getInstance();
        if (core == null) {
            return RcsServiceRegistration.ReasonCode.UNSPECIFIED;
        }
        ImsNetworkInterface networkInterface = core.getImsModule().getCurrentNetworkInterface();
        if (networkInterface == null) {
            return RcsServiceRegistration.ReasonCode.UNSPECIFIED;
        }
        return networkInterface.getRegistrationReasonCode();
    }

    /**
     * Checks if extension is authorized for an application. Application is identified by its uid
     * 
     * @param packageUid
     * @param serviceId
     * @throws ServerPermissionDeniedException
     */
    public static void assertExtensionIsAuthorized(Integer packageUid, String serviceId)
            throws ServerPermissionDeniedException {

        ExtensionManager extensionManager = ExtensionManager.getInstance();
        if (extensionManager.isNativeApplication(packageUid)) {
            if (logger.isActivated()) {
                logger.info("assertExtensionIsAuthorized : no control for native application");
            }
            return;
        }
        extensionManager.testExtensionPermission(packageUid, serviceId);
    }

    /**
     * Checks if API access is authorized for an application. Application is identified by its uid
     * 
     * @param packageUid
     * @param extensionType
     * @throws ServerPermissionDeniedException
     */
    public static void assertApiIsAuthorized(Integer packageUid, Extension.Type extensionType)
            throws ServerPermissionDeniedException {

        ExtensionManager extensionManager = ExtensionManager.getInstance();
        if (extensionManager.isNativeApplication(packageUid)) {
            if (logger.isActivated()) {
                logger.info("assertApiIsAuthorized : no control for native application");
            }
            return;
        }
        extensionManager.testApiPermission(packageUid, extensionType);
    }

    /**
     * Add IARI (application Identifier) as features tag in IMS session for third party application
     * 
     * @param featureTags
     * @param callingUid
     */
    public static void addApplicationIdAsFeaturesTag(List<String> featureTags, Integer callingUid) {
        boolean isActivated = logger.isActivated();
        if (isActivated) {
            logger.debug("addApplicationIdAsFeaturesTag , callingUid : ".concat(String
                    .valueOf(callingUid)));
        }

        ExtensionManager extensionManager = ExtensionManager.getInstance();
        if (extensionManager.isNativeApplication(callingUid)) {
            if (isActivated) {
                logger.debug("   --> no control for native application");
            }
            return;
        }

        String iari = extensionManager.getApplicationId(callingUid);
        if (iari == null) {
            if (isActivated) {
                logger.debug(" --> no authorization found");
            }
            return;
        }
        iari = new StringBuilder(FeatureTags.FEATURE_RCSE_EXTENSION).append(".").append(iari).toString();
        
        for (int i=0;i<featureTags.size();i++) {     
            if(featureTags.get(i).startsWith(FeatureTags.FEATURE_RCSE)){
                String featureTag = featureTags.get(i); 
                featureTags.set(i, new StringBuilder(featureTag).insert(featureTag.length()-1,",".concat(iari)).toString());
                return;
            }
        }
                        
        String appRef = new StringBuilder(FeatureTags.FEATURE_RCSE).append("=\"").append(iari).append("\"").toString();

        if (isActivated) {
            logger.debug(" --> iari : ".concat(appRef));
        }
        featureTags.add(appRef);
    }
}
