/*
 * Copyright 2013, France Telecom
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gsma.rcs.core.ims.protocol.rtp.format.video;

/**
 * Class H264VideoFormat.
 */
public class H264VideoFormat extends VideoFormat {
    /**
     * Constant ENCODING.
     */
    public static final String ENCODING = "H264";

    /**
     * Constant PAYLOAD.
     */
    public static final int PAYLOAD = 96;

    /**
     * Creates a new instance of H264VideoFormat.
     */
    public H264VideoFormat() {
        super((java.lang.String) null, 0);
    }

} // end H264VideoFormat