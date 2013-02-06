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

package org.gsma.rcs.core.ims.protocol.rtp.stream;

/**
 * Class ProcessorOutputStream.
 */
public interface ProcessorOutputStream {
    /**
     *  
     * @param arg1 The arg1.
     */
    public void write(org.gsma.rcs.core.ims.protocol.rtp.util.Buffer arg1) throws Exception;

    public void close();

    public void open() throws Exception;

} // end ProcessorOutputStream