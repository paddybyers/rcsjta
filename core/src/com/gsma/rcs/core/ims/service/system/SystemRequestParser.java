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

import com.gsma.rcs.utils.logger.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

/**
 * System request parser
 *
 * @author jexa7410
 */
public class SystemRequestParser extends DefaultHandler {
    /*
     * SAMPLE: <?xml version="1.0" encoding="UTF-8"?> <xs:schema
     * xmlns:xs="http://www.w3.org/2001/XMLSchema" elementFormDefault="qualified"> <xs:element
     * name="SystemRequest"> <xs:complexType> <xs:attribute name="id" type="xs:string"
     * use="required"/> <xs:attribute name="type" type="xs:string" use="required"/> <xs:attribute
     * name="data" type="xs:string" use="optional"/> </xs:complexType> </xs:element> </xs:schema>
     */

    /**
     * Char buffer for parsing text from one element
     */
    private StringBuffer accumulator;

    /**
     * Revoked extensions
     */
    private List<String> revoked = new ArrayList<String>();

    /**
     * The logger
     */
    private Logger logger = Logger.getLogger(this.getClass().getName());

    /**
     * Constructor
     *
     * @param inputSource Input source
     * @throws Exception
     */
    public SystemRequestParser(InputSource inputSource) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        parser.parse(inputSource, this);
    }

    /**
     * @return list of revoked extensions
     */
    public List<String> getRevokedExtensions() {
        return revoked;
    }

    public void startDocument() {
        if (logger.isActivated()) {
            logger.debug("Start document");
        }
        accumulator = new StringBuffer();
    }

    public void characters(char buffer[], int start, int length) {
        accumulator.append(buffer, start, length);
    }

    public void startElement(String namespaceURL, String localName, String qname, Attributes attr) {
        accumulator.setLength(0);

        if (localName.equals("SystemRequest")) {
            String type = attr.getValue("type").trim();
            String data = attr.getValue("data").trim();
            if (type.equals("urn:gsma:rcs:extension:control")) {
                // (<IARI>,<duration>) separated by ";"
                StringTokenizer st = new StringTokenizer(data, ";");
                while (st.hasMoreTokens()) {
                    String token = st.nextToken();
                    String iari = token.substring(1, token.length() - 1);
                    revoked.add(iari);
                }
            }
        }
    }

    public void endElement(String namespaceURL, String localName, String qname) {
        if (qname.equals("SystemRequest")) {
            if (logger.isActivated()) {
                logger.debug("SystemRequest document is complete");
            }
        }
    }

    public void endDocument() {
        if (logger.isActivated()) {
            logger.debug("End document");
        }
    }
}
