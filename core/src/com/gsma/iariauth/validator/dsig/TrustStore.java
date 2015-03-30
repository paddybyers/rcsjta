/*
 * Copyright (C) 2014 GSM Association
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package com.gsma.iariauth.validator.dsig;

import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * An interface to a repository of trust anchors for signature validation.
 */
public interface TrustStore {

    /**
     * Get the applicable trust anchors for a given IARI range
     * 
     * @param range: the range string
     */
    public Set<TrustAnchor> getTrustAnchorsForRange(String range);
}
