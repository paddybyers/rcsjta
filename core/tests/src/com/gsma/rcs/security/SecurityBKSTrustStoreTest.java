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

package com.gsma.rcs.security;

import java.io.IOException;
import java.io.InputStream;

import android.test.AndroidTestCase;

import com.gsma.iariauth.validator.PackageProcessor;
import com.gsma.iariauth.validator.ProcessingResult;
import com.gsma.rcs.core.ims.service.extension.BKSTrustStore;
import com.gsma.rcs.provider.LocalContentResolver;
import com.gsma.rcs.provider.security.CertificateData;
import com.gsma.rcs.provider.security.SecurityLog;

/**
 * Test the security model
 * 
 * @author JEXA7410
 */
public class SecurityBKSTrustStoreTest extends AndroidTestCase {

    private LocalContentResolver mContentResolver;
    private SecurityLog mSecurityInfos;
    private SecurityLibTest mSecurityInfosTest;

    protected void setUp() throws Exception {
        super.setUp();
        mContentResolver = new LocalContentResolver(getContext().getContentResolver());
        SecurityLog.createInstance(mContentResolver);
        mSecurityInfos = SecurityLog.getInstance();
        mSecurityInfosTest = new SecurityLibTest();
        mSecurityInfosTest.removeAllCertificates(mContentResolver);
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        mSecurityInfosTest.removeAllCertificates(mContentResolver);
    }

    private final static String PKG_NAME = "com.gsma.iariauth.sample";
    private static final String FINGER_PRINT = "1E:74:D2:9A:21:FC:D8:6E:66:28:D9:DE:A9:FB:38:B5:04:01:10:28";

    private final static String IARI_DOC = "assets/iari-range-test.xml";
    private final static String CERTIF_DOC = "assets/range-root.crt";

    public void testBKSTrustore() {
        BKSTrustStore mTrustore;

        InputStream iariDocFis = null;
        InputStream storeFis = null;
        InputStream certifFis = null;
        try {
            mTrustore = new BKSTrustStore(mSecurityInfos);

            iariDocFis = getClass().getClassLoader().getResourceAsStream(IARI_DOC);
            assertNotNull(iariDocFis);

            certifFis = getClass().getClassLoader().getResourceAsStream(CERTIF_DOC);
            assertNotNull(certifFis);

            // Read certificate from file
            StringBuilder certif = new StringBuilder();
            int ch;
            while ((ch = certifFis.read()) != -1) {
                certif.append((char) ch);
            }
            // insert into provider
            mSecurityInfos.addCertificate(new CertificateData(
                    "urn:urn-7:3gpp-application.ims.iari.rcs.mnc099.mcc099.*", certif.toString()));

            // Check validity of iari authorization doc
            PackageProcessor processor = new PackageProcessor(mTrustore, PKG_NAME, FINGER_PRINT);
            ProcessingResult result = processor.processIARIauthorization(iariDocFis);

            assertEquals(ProcessingResult.STATUS_OK, result.getStatus());

        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        } finally {
            if (iariDocFis != null) {
                try {
                    iariDocFis.close();
                } catch (IOException e) {
                }
            }
            if (storeFis != null) {
                try {
                    storeFis.close();
                } catch (IOException e) {
                }
            }
            if (certifFis != null) {
                try {
                    certifFis.close();
                } catch (IOException e) {
                }
            }
        }
    }

}
