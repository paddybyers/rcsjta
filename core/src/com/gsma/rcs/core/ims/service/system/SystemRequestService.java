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

package com.gsma.rcs.core.ims.service.system;

import com.gsma.rcs.core.CoreException;
import com.gsma.rcs.core.ims.ImsModule;
import com.gsma.rcs.core.ims.network.sip.SipMessageFactory;
import com.gsma.rcs.core.ims.protocol.sip.SipRequest;
import com.gsma.rcs.core.ims.protocol.sip.SipResponse;
import com.gsma.rcs.core.ims.service.ImsService;
import com.gsma.rcs.core.ims.service.extension.SupportedExtensionUpdater;
import com.gsma.rcs.utils.IdGenerator;
import com.gsma.rcs.utils.logger.Logger;

import java.io.ByteArrayInputStream;

import org.xml.sax.InputSource;

/**
 * End user system request service
 * 
 * @author jexa7410
 */
public class SystemRequestService extends ImsService {
    /**
     * The logger
     */
    private Logger logger = Logger.getLogger(this.getClass().getName());

    /**
     * Constructor
     * 
     * @param parent IMS module
     * @throws CoreException
     */
    public SystemRequestService(ImsModule parent) throws CoreException {
        super(parent, true);
    }

    /**
     * Start the IMS service
     */
    public synchronized void start() {
        if (isServiceStarted()) {
            // Already started
            return;
        }
        setServiceStarted(true);
    }

    /**
     * Stop the IMS service
     */
    public synchronized void stop() {
        if (!isServiceStarted()) {
            // Already stopped
            return;
        }
        setServiceStarted(false);
    }

    /**
     * Check the IMS service
     */
    public void check() {
    }

    /**
     * Receive a SIP message
     * 
     * @param message Received message
     */
    public void receiveMessage(SipRequest message) {
        if (logger.isActivated()) {
            logger.debug("Receive system request");
        }

        // Send a 200 OK response
        try {
            if (logger.isActivated()) {
                logger.info("Send 200 OK");
            }
            SipResponse response = SipMessageFactory.createResponse(message,
                    IdGenerator.getIdentifier(), 200);
            getImsModule().getSipManager().sendSipResponse(response);
        } catch (Exception e) {
            if (logger.isActivated()) {
                logger.error("Can't send 200 OK response", e);
            }
            return;
        }

        // Parse received request
        try {
            // Parse system request
            InputSource input = new InputSource(new ByteArrayInputStream(message.getContentBytes()));
            SystemRequestParser parser = new SystemRequestParser(input);

            // Update the security model
            SupportedExtensionUpdater.revokeExtensions(parser.getRevokedExtensions());
        } catch (Exception e) {
            if (logger.isActivated()) {
                logger.error("Can't parse system request", e);
            }
        }
    }

    /**
     * Is a system request
     * 
     * @param request Request
     * @return Boolean
     */
    public static boolean isSystemRequest(SipRequest request) {
        String contentType = request.getContentType();
        if ((contentType != null) && contentType.startsWith("application/system-request+xml")) {
            return true;
        } else {
            return false;
        }
    }
}
