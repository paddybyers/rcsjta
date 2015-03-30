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

import java.lang.reflect.Field;
import java.util.Map;

import android.test.AndroidTestCase;

import com.gsma.iariauth.validator.IARIAuthDocument.AuthType;
import com.gsma.rcs.core.ims.service.extension.Extension;
import com.gsma.rcs.provider.LocalContentResolver;
import com.gsma.rcs.provider.security.AuthorizationData;
import com.gsma.rcs.provider.security.CacheAuth;
import com.gsma.rcs.provider.security.CertificateData;
import com.gsma.rcs.provider.security.RevocationData;
import com.gsma.rcs.provider.security.SecurityLog;

public class SecurityProviderTest extends AndroidTestCase {

    private final static int REV_AUTHORIZED = -1;
    private final static int REV_REVOKED_INFINITE = 0;

    private String cert1 = "certificate1";

    private String cert2 = "certificate2";

    private String iari1 = "urn:urn-7:3gpp-application.ims.iari.rcs.mnc099.mcc099.demo1";
    private String range1 = "urn:urn-7:3gpp-application.ims.iari.rcs.mnc099.mcc099.*";

    private String iari2 = "urn:urn-7:3gpp-application.ims.iari.rcs.mnc000.mcc000.demo2";
    private String range2 = "urn:urn-7:3gpp-application.ims.iari.rcs.mnc000.mcc000.*";

    private final Integer UID1 = 100000;
    private final Integer UID2 = 100001;
    private final Integer UID3 = 100002;

    private SecurityLog mSecurityInfos;

    private LocalContentResolver mContentResolver;

    private CertificateData mIariRange1Cert1;
    private CertificateData mIariRange1Cert2;
    private CertificateData mIariRange2Cert1;
    private CertificateData mIariRange2Cert2;

    private AuthorizationData mAuth1;
    private AuthorizationData mAuth2;
    private AuthorizationData mAuth3;
    private AuthorizationData mAuth4;

    private RevocationData mRev1;
    private RevocationData mRev2;

    private SecurityLibTest mSecurityInfosTest;

    protected void setUp() throws Exception {
        super.setUp();

        mContentResolver = new LocalContentResolver(getContext().getContentResolver());
        SecurityLog.createInstance(mContentResolver);
        mSecurityInfos = SecurityLog.getInstance();
        mIariRange1Cert1 = new CertificateData(iari1, cert1);
        mIariRange1Cert2 = new CertificateData(iari1, cert2);
        mIariRange2Cert1 = new CertificateData(iari2, cert1);
        mIariRange2Cert2 = new CertificateData(iari2, cert2);
        mAuth1 = new AuthorizationData(UID1, "com.orangelabs.package1", new Extension(iari1,
                Extension.Type.APPLICATION_ID), AuthType.RANGE, range1, "99:99:99");
        mAuth2 = new AuthorizationData(UID2, "com.orangelabs.package2", new Extension(iari2,
                Extension.Type.MULTIMEDIA_SESSION), AuthType.RANGE, range2, "00:00:00");
        mAuth3 = new AuthorizationData(UID3, "com.orangelabs.package3", new Extension("demo3",
                Extension.Type.MULTIMEDIA_SESSION));
        mAuth4 = new AuthorizationData(UID3, "com.orangelabs.package3", new Extension("demo4",
                Extension.Type.MULTIMEDIA_SESSION));
        mSecurityInfosTest = new SecurityLibTest();
        mSecurityInfosTest.removeAllCertificates(mContentResolver);
        mSecurityInfosTest.removeAllAuthorizations(mContentResolver);

        mRev1 = new RevocationData(iari1, REV_AUTHORIZED);
        mRev2 = new RevocationData(iari2, REV_REVOKED_INFINITE);
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        mSecurityInfosTest.removeAllCertificates(mContentResolver);
        mSecurityInfosTest.removeAllAuthorizations(mContentResolver);
        mSecurityInfosTest.removeAllRevocations(mContentResolver);
    }

    public void testAddCertificate() {
        Map<CertificateData, Integer> map = mSecurityInfos.getAllCertificates();
        assertEquals(0, map.size());

        mSecurityInfos.addCertificate(mIariRange1Cert1);
        Integer id = mSecurityInfosTest.getIdForIariAndCertificate(mContentResolver,
                mIariRange1Cert1);
        assertNotSame(id, SecurityLibTest.INVALID_ID);
        map = mSecurityInfos.getAllCertificates();
        assertEquals(1, map.size());

        assertTrue(map.containsKey(mIariRange1Cert1));

        assertTrue(map.get(mIariRange1Cert1).equals(id));

        mSecurityInfos.addCertificate(mIariRange1Cert1);
        Integer new_id = mSecurityInfosTest.getIdForIariAndCertificate(mContentResolver,
                mIariRange1Cert1);
        assertEquals(id, new_id);

        map = mSecurityInfos.getAllCertificates();
        assertEquals(1, map.size());
        assertTrue(map.containsKey(mIariRange1Cert1));
        assertEquals(map.get(mIariRange1Cert1), id);
    }

    public void testRemoveCertificate() {
        mSecurityInfos.addCertificate(mIariRange1Cert1);
        int id = mSecurityInfosTest.getIdForIariAndCertificate(mContentResolver, mIariRange1Cert1);
        assertNotSame(id, SecurityLibTest.INVALID_ID);
        int count = mSecurityInfos.removeCertificate(id);
        assertEquals(1, count);
        Map<CertificateData, Integer> map = mSecurityInfos.getAllCertificates();
        assertEquals(0, map.size());
    }

    public void testGetAllCertificates() {
        mSecurityInfos.addCertificate(mIariRange1Cert1);
        Map<CertificateData, Integer> map = mSecurityInfos.getAllCertificates();
        assertEquals(1, map.size());

        mSecurityInfos.addCertificate(mIariRange1Cert2);
        map = mSecurityInfos.getAllCertificates();
        assertEquals(2, map.size());
        assertTrue(map.containsKey(mIariRange1Cert1));
        assertTrue(map.containsKey(mIariRange1Cert2));

        mSecurityInfos.addCertificate(mIariRange2Cert1);
        map = mSecurityInfos.getAllCertificates();
        assertEquals(3, map.size());
        assertTrue(map.containsKey(mIariRange1Cert1));
        assertTrue(map.containsKey(mIariRange1Cert2));
        assertTrue(map.containsKey(mIariRange2Cert1));

        mSecurityInfos.addCertificate(mIariRange2Cert2);
        map = mSecurityInfos.getAllCertificates();
        assertEquals(4, map.size());
        assertTrue(map.containsKey(mIariRange1Cert1));
        assertTrue(map.containsKey(mIariRange1Cert2));
        assertTrue(map.containsKey(mIariRange2Cert1));
        assertTrue(map.containsKey(mIariRange2Cert2));
    }

    public void testGetAllAuthorizations() {
        Map<AuthorizationData, Integer> authorizationDatas = mSecurityInfos.getAllAuthorizations();
        assertEquals(0, authorizationDatas.size());

        mSecurityInfos.addAuthorization(mAuth1);
        authorizationDatas = mSecurityInfos.getAllAuthorizations();
        assertEquals(1, authorizationDatas.size());
        assertTrue(authorizationDatas.containsKey(mAuth1));

        mSecurityInfos.addAuthorization(mAuth2);
        authorizationDatas = mSecurityInfos.getAllAuthorizations();
        assertEquals(2, authorizationDatas.size());
        assertTrue(authorizationDatas.containsKey(mAuth1));
        assertTrue(authorizationDatas.containsKey(mAuth2));

        mSecurityInfos.addAuthorization(mAuth3);
        authorizationDatas = mSecurityInfos.getAllAuthorizations();
        assertEquals(3, authorizationDatas.size());
        assertTrue(authorizationDatas.containsKey(mAuth1));
        assertTrue(authorizationDatas.containsKey(mAuth2));
        assertTrue(authorizationDatas.containsKey(mAuth3));

        mSecurityInfos.addAuthorization(mAuth4);
        authorizationDatas = mSecurityInfos.getAllAuthorizations();
        assertEquals(4, authorizationDatas.size());
        assertTrue(authorizationDatas.containsKey(mAuth1));
        assertTrue(authorizationDatas.containsKey(mAuth2));
        assertTrue(authorizationDatas.containsKey(mAuth3));
        assertTrue(authorizationDatas.containsKey(mAuth4));
    }

    public void testAddAuthorization() {

        mSecurityInfos.addAuthorization(mAuth1);
        Integer id = mSecurityInfosTest.getIdForPackageUidAndIari(mContentResolver, UID1,
                "urn:urn-7:3gpp-application.ims.iari.rcs.mnc099.mcc099.demo1");
        assertNotSame(id, SecurityLibTest.INVALID_ID);

        Map<AuthorizationData, Integer> authorizationDatas = mSecurityInfos.getAllAuthorizations();
        assertEquals(1, authorizationDatas.size());

        assertTrue(authorizationDatas.containsKey(mAuth1));

        assertEquals(id, authorizationDatas.get(mAuth1));

        mSecurityInfos.addAuthorization(mAuth1);
        Integer new_id = mSecurityInfosTest.getIdForPackageUidAndIari(mContentResolver, UID1,
                "urn:urn-7:3gpp-application.ims.iari.rcs.mnc099.mcc099.demo1");
        assertEquals(id, new_id);

        authorizationDatas = mSecurityInfos.getAllAuthorizations();
        assertEquals(1, authorizationDatas.size());
        assertTrue(authorizationDatas.containsKey(mAuth1));
        assertEquals(authorizationDatas.get(mAuth1), id);
    }

    public void testRemoveAuthorization() {

        mSecurityInfos.addAuthorization(mAuth1);
        int id = mSecurityInfosTest.getIdForPackageUidAndIari(mContentResolver, UID1,
                "urn:urn-7:3gpp-application.ims.iari.rcs.mnc099.mcc099.demo1");
        assertNotSame(id, SecurityLibTest.INVALID_ID);
        int count = mSecurityInfos.removeAuthorization(id, mAuth1.getExtension()
                .getExtensionAsIari());
        assertEquals(1, count);
        Map<AuthorizationData, Integer> map = mSecurityInfos.getAllAuthorizations();
        assertEquals(0, map.size());
    }

    public void testGetAuthorization() {

        Integer id1, id2;
        AuthorizationData localAuth;

        Map<AuthorizationData, Integer> authorizationDatas = mSecurityInfos.getAllAuthorizations();
        assertEquals(0, authorizationDatas.size());

        mSecurityInfos.addAuthorization(mAuth1);
        authorizationDatas = mSecurityInfos.getAllAuthorizations();
        assertEquals(1, authorizationDatas.size());
        assertTrue(authorizationDatas.containsKey(mAuth1));

        id1 = mSecurityInfosTest.getIdForPackageUidAndIari(mContentResolver, UID1, mAuth1
                .getExtension().getExtensionAsIari());
        id2 = mSecurityInfosTest.getIdForPackageUidAndIari(mContentResolver, UID1, mAuth1
                .getExtension().getExtensionAsIari());
        assertEquals(id1, id2);

        localAuth = mSecurityInfosTest.getAuthorizationById(mContentResolver, id1);
        assertEquals(mAuth1, localAuth);

        localAuth = mSecurityInfos.getAuthorizationByUidAndIari(mAuth1.getPackageUid(), mAuth1
                .getExtension().getExtensionAsIari());
        assertEquals(mAuth1, localAuth);

        assertEquals(id1,
                mSecurityInfos.getAuthorizationIdByIARI(mAuth1.getExtension().getExtensionAsIari()));
        assertEquals(Integer.valueOf(SecurityLog.INVALID_ID),
                mSecurityInfos.getAuthorizationIdByIARI("notExistingIARI"));
    }

    public void testRevocations() {
        Map<RevocationData, Integer> revocationDatas = mSecurityInfosTest
                .getAllRevocations(mContentResolver);
        assertEquals(0, revocationDatas.size());
        assertEquals(0, getCacheForRevocationAuth(mSecurityInfos).size());

        // Add
        mSecurityInfos.addRevocation(mRev1);
        revocationDatas = mSecurityInfosTest.getAllRevocations(mContentResolver);
        int revId1 = mSecurityInfos.getIdForRevocation(mRev1.getServiceId());
        assertNotSame(revId1, SecurityLibTest.INVALID_ID);
        assertEquals(1, revocationDatas.size());
        assertEquals(1, getCacheForRevocationAuth(mSecurityInfos).size());
        assertTrue(revocationDatas.containsKey(mRev1));

        mSecurityInfos.addRevocation(mRev2);
        int revId2 = mSecurityInfos.getIdForRevocation(mRev2.getServiceId());
        assertNotSame(revId1, SecurityLibTest.INVALID_ID);
        revocationDatas = mSecurityInfosTest.getAllRevocations(mContentResolver);
        assertEquals(2, revocationDatas.size());
        assertEquals(2, getCacheForRevocationAuth(mSecurityInfos).size());
        assertTrue(revocationDatas.containsKey(mRev1));
        assertTrue(revocationDatas.containsKey(mRev2));

        // Update
        RevocationData localRev1 = new RevocationData(mRev1.getServiceId(), 1000L);
        RevocationData localRev2 = new RevocationData(mRev2.getServiceId(), 2000L);
        mSecurityInfos.addRevocation(localRev1);
        mSecurityInfos.addRevocation(localRev1);
        revocationDatas = mSecurityInfosTest.getAllRevocations(mContentResolver);
        assertEquals(2, revocationDatas.size());
        assertEquals(2, getCacheForRevocationAuth(mSecurityInfos).size());
        assertEquals(revId1, mSecurityInfos.getIdForRevocation(localRev1.getServiceId()));
        assertEquals(revId2, mSecurityInfos.getIdForRevocation(localRev2.getServiceId()));

        // Remove
        mSecurityInfos.removeRevocation(localRev1.getServiceId());
        revocationDatas = mSecurityInfosTest.getAllRevocations(mContentResolver);
        assertEquals(1, revocationDatas.size());
        assertEquals(1, getCacheForRevocationAuth(mSecurityInfos).size());
        mSecurityInfos.removeRevocation(localRev2.getServiceId());
        revocationDatas = mSecurityInfosTest.getAllRevocations(mContentResolver);
        assertEquals(0, revocationDatas.size());
        assertEquals(0, getCacheForRevocationAuth(mSecurityInfos).size());
    }

    public void testCacheAuthorization() {

        CacheAuth cacheAuth = new CacheAuth();
        cacheAuth.add(mAuth1);
        assertEquals(mAuth1, cacheAuth.get(iari1));
        assertEquals(mAuth1, cacheAuth.get(UID1, iari1));

        cacheAuth.remove(iari1);
        assertNull(cacheAuth.get(iari1));
        assertNull(cacheAuth.get(UID1, iari1));
    }

    @SuppressWarnings("unchecked")
    public Map<String, Integer> getCacheForRevocationAuth(SecurityLog securityLog) {
        Field cacheField;
        try {
            cacheField = SecurityLog.class.getDeclaredField("mCacheRev");
            cacheField.setAccessible(true);
            return (Map<String, Integer>) cacheField.get(securityLog);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
