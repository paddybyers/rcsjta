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

package com.gsma.rcs.security;

import com.gsma.rcs.core.ims.service.extension.ICertificateProvisioningListener;
import com.gsma.rcs.provider.LocalContentResolver;
import com.gsma.rcs.provider.security.CertificateData;
import com.gsma.rcs.provider.security.SecurityLog;
import com.gsma.rcs.provider.settings.RcsSettings;
import com.gsma.rcs.provider.settings.RcsSettingsData.ExtensionPolicy;
import com.gsma.rcs.provider.settings.RcsSettingsData.GsmaRelease;
import com.gsma.rcs.provisioning.ProvisioningParser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;

import android.test.AndroidTestCase;

/**
 * Test the security model
 * 
 * @author JEXA7410
 */
public class SecurityCertificateProvisioningTest extends AndroidTestCase {

    private RcsSettings mRcsSettings;
    private Set<CertificateData> mMemoryData;

    protected void setUp() throws Exception {
        super.setUp();

        LocalContentResolver localContentResolver = new LocalContentResolver(getContext().getContentResolver());
        mRcsSettings = RcsSettings.createInstance(localContentResolver);
        SecurityLog.createInstance(localContentResolver);        
    }

    protected void tearDown() throws Exception {
        super.tearDown();
    }

    private String loadConfigFile(String file) {
        InputStream inputStream = null;
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            inputStream = this.getClass().getClassLoader().getResourceAsStream(file);
            int i;
            i = inputStream.read();
            while (i != -1) {
                outputStream.write(i);
                i = inputStream.read();
            }
            return outputStream.toString();
        } catch (Exception e) {
            return null;
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                }
            }
        }
    }

    public void testAuthorized() {
        String content = loadConfigFile("assets/template-ota_config-allowed.xml");
        mMemoryData = null;
        ProvisioningParser parser = new ProvisioningParser(content, mRcsSettings,
                new ICertificateProvisioningListener() {

                    @Override
                    public void stop() {

                    }

                    @Override
                    public void start() {
                        mMemoryData = new HashSet<CertificateData>();
                    }

                    @Override
                    public void addNewCertificate(String iari, String certificate) {
                        CertificateData iariRangeCertificate = new CertificateData(iari,
                                certificate);
                        mMemoryData.add(iariRangeCertificate);
                    }
                });
        GsmaRelease gsmaRelease = mRcsSettings.getGsmaRelease();
        boolean result = parser.parse(gsmaRelease, true);
        assertTrue(result);
        assertTrue(mRcsSettings.isExtensionsAllowed());

        assertNotNull(mMemoryData);
        for (CertificateData iariRangeCertificate : mMemoryData) {
            String iariRange = iariRangeCertificate.getIARIRange();
            String cert = iariRangeCertificate.getCertificate();
            if (!iariRange.equals("urn:urn-7:3gpp-application.ims.iari.rcs.mnc099.mcc099.demo1")) {
                if (!iariRange
                        .equals("urn:urn-7:3gpp-application.ims.iari.rcs.mnc099.mcc099.demo2")) {
                    fail("IARI not found ".concat(iariRange));
                } else {
                    assertEquals(
                            "MIIDEzCCAfugAwIBAgIERnLjKTANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDEw1t_2A",
                            cert);
                }
            } else {
                if (!cert
                        .equals("MIIDEzCCAfugAwIBAgIERnLjKTANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDEw1t_1A")) {
                    if (!cert
                            .equals("MIIDEzCCAfugAwIBAgIERnLjKTANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDEw1t_1B")) {
                        fail("Certificate not found ".concat(cert));
                    }
                }
            }
        }
    }

    public void testNotAllowed() {
        String content = loadConfigFile("assets/template-ota_config-not-allowed.xml");
        ProvisioningParser parser = new ProvisioningParser(content, mRcsSettings, null);
        GsmaRelease gsmaRelease = mRcsSettings.getGsmaRelease();
        boolean result = parser.parse(gsmaRelease, true);
        assertTrue(result);
        assertFalse(mRcsSettings.isExtensionsAllowed());
    }

    public void testIariAllowed() {
        String content = loadConfigFile("assets/template-ota_config-allowed.xml");
        ProvisioningParser parser = new ProvisioningParser(content, mRcsSettings, null);
        GsmaRelease gsmaRelease = mRcsSettings.getGsmaRelease();
        boolean result = parser.parse(gsmaRelease, true);
        assertTrue(result);
        assertTrue(mRcsSettings.isExtensionsAllowed());
    }

    public void testMnoApp() {
        String content = loadConfigFile("assets/template-ota_config-allowed-mno.xml");
        ProvisioningParser parser = new ProvisioningParser(content, mRcsSettings, null);
        GsmaRelease gsmaRelease = mRcsSettings.getGsmaRelease();
        boolean result = parser.parse(gsmaRelease, true);
        assertTrue(result);
        assertEquals(mRcsSettings.getExtensionspolicy(), ExtensionPolicy.ONLY_MNO);
    }

    public void test3ppApp() {
        String content = loadConfigFile("assets/template-ota_config-allowed-3pp.xml");
        ProvisioningParser parser = new ProvisioningParser(content, mRcsSettings, null);
        GsmaRelease gsmaRelease = mRcsSettings.getGsmaRelease();
        boolean result = parser.parse(gsmaRelease, true);
        assertTrue(result);
        assertEquals(mRcsSettings.getExtensionspolicy(), ExtensionPolicy.MNO_THIRD_PARTTY);
    }
}
