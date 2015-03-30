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

package com.gsma.rcs.core.ims.service.extension;

import com.gsma.iariauth.validator.Constants;
import com.gsma.rcs.core.ims.network.sip.FeatureTags;

/**
 * IARI utils
 * 
 * @author LEMORDANT Philippe
 */
public class IARIUtils {

    /**
     * 2nd party apps extension prefix
     */
    private static final String MNO_IARI_PREFIX = "urn:urn-7:3gpp-application.ims.iari.rcs.mnc";

    /**
     * Common prefix
     */
    public static final String COMMON_PREFIX = "urn:urn-7:3gpp-application.ims.iari.rcs.";

    /**
     * Is a valid IARI
     * 
     * @param iari
     * @return True if IARI is valid
     */
    public static boolean isValidIARI(String iari) {
        return isMnoIARI(iari) || isThirdPartyIARI(iari);
    }

    /**
     * Is a MNO extension
     * 
     * @param iari
     * @return True is extension MNO
     */
    public static boolean isMnoIARI(String iari) {
        return iari.startsWith(MNO_IARI_PREFIX);
    }

    /**
     * Is a third party IARI
     * 
     * @param iari
     * @return True if IARI is from third party
     */
    public static boolean isThirdPartyIARI(String iari) {
        return iari.startsWith(Constants.STANDALONE_IARI_PREFIX);
    }

    /**
     * Build IARI from extension
     * 
     * @param extension
     * @return IARI
     */
    public static String getIARI(String extension) {
        return COMMON_PREFIX.concat(extension);
    }

    /**
     * Return the serviceId from IARI
     * 
     * @param iari
     * @return serviceId
     */
    public static String getServiceId(String iari) {
        if (iari.startsWith(COMMON_PREFIX)) {
            return iari.substring(COMMON_PREFIX.length());
        } else if (iari.startsWith(FeatureTags.FEATURE_RCSE_EXTENSION)) {
            return iari.substring(FeatureTags.FEATURE_RCSE_EXTENSION.length() + 1);
        }
        return null;
    }
}
