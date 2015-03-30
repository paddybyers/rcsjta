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

/**
 * An interface to handle events when parsing X509 certificates from the provisioning
 * 
 * @author P.LEMORDANT
 */
public interface ICertificateProvisioningListener {

    /**
     * Method called once first iariAuthorizationInfo node is detected
     */
    void start();

    /**
     * Method called once last iariAuthorizationInfo node is parsed successfully
     */
    void stop();

    /**
     * Method called once a X509 certificate is parsed
     * 
     * @param iari
     * @param certificate
     */
    void addNewCertificate(String iari, String certificate);

}
