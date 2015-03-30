
package com.gsma.rcs.system;

import com.gsma.rcs.core.ims.service.system.SystemRequestParser;

import java.io.ByteArrayInputStream;
import java.util.List;

import org.xml.sax.InputSource;

import android.test.AndroidTestCase;

public class SystemRequestParserTest extends AndroidTestCase {
    private static final String CRLF = "\r\n";

    private final static String EXT1 = "urn%3Aurn-7%3A3gppapplication.ims.iari.rcs.ext.A5TgS99bJloIUIh1209SJ82B21m87S1B87SBqfS871BS8787SBXBA3P45wjp63tk,0";

    private final static String EXT2 = "urn%3Aurn-7%3A3gppapplication.ims.iari.rcs.ext.VoxgS94bJloIUIh12r9Sop1j21m87Spt83SZqfS871BS128pSB2B13P42wjp43rt,3600";

    protected void setUp() throws Exception {
        super.setUp();
    }

    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testSystemRequest() {
        String data = "(" + EXT1 + ");(" + EXT2 + ")";
        StringBuffer sb = new StringBuffer("<?xml version=\"1.08\" encoding=\"UTF-8\"?>");
        sb.append(CRLF);
        sb.append("<SystemRequest id=\"999\" type=\"urn:gsma:rcs:extension:control\" data=\""
                + data + "\">");
        sb.append(CRLF);
        sb.append("</SystemRequest>");
        String xml = sb.toString();
        try {
            InputSource inputso = new InputSource(new ByteArrayInputStream(xml.getBytes()));
            SystemRequestParser parser = new SystemRequestParser(inputso);
            List<String> exts = parser.getRevokedExtensions();
            String ext1 = exts.get(0);
            String ext2 = exts.get(1);
            assertEquals(ext1, EXT1);
            assertEquals(ext2, EXT2);
        } catch (Exception e) {
            fail("no Conference info source parsed");
            e.printStackTrace();
        }
    }
}
