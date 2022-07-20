/*
 * Copyright 2019 Okta
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.tools.authentication;

import com.okta.tools.helpers.CookieHelper;

import java.io.IOException;
import java.net.CookieHandler;
import java.net.URI;
import java.util.*;

/**
 * Adaptor for {@link com.sun.webkit.network.CookieManager} that stores cookies
 */
public final class CookieManager extends CookieHandler {
    private final CookieHandler cookieHandler = CookieHandler.getDefault();
    private final CookieHelper cookieHelper;
    private final String targetDomain;

    public CookieManager(CookieHelper cookieHelper, URI targetUri) {
        this.cookieHelper = cookieHelper;
        this.targetDomain = targetUri.getHost();
    }

    @Override
    public Map<String, List<String>> get(URI uri, Map<String,List<String>> requestHeaders) throws IOException
    {
        return cookieHandler.get(uri, requestHeaders);
    }

    @Override
    public void put(URI uri, Map<String,List<String>> responseHeaders) throws IOException {

        //temp (un)fix for java-fx cookies reversal temp fix for https://bugs.java.com/bugdatabase/view_bug.do?bug_id=7059532
        responseHeaders = fixCookie(uri, responseHeaders);

        if (uri.getAuthority().equals(targetDomain)) {
            cookieHelper.storeCookies(responseHeaders);
        }
        cookieHandler.put(uri, responseHeaders);
    }

    private Map<String,List<String>> fixCookie(URI uri, Map<String,List<String>> responseHeaders)  {
        Map<String, List<String>> res = new HashMap<>();
        if (responseHeaders == null) {
            return res;
        }

        for (Map.Entry<String,List<String>> entry : responseHeaders.entrySet())
        {
            String key = entry.getKey();
            if (!"Set-Cookie".equalsIgnoreCase(key)) {
                res.put(key, entry.getValue());
                continue;
            }

            List<String> attrs = new ArrayList<>();
            ListIterator<String> it = entry.getValue().listIterator(entry.getValue().size());

            while (it.hasPrevious()) {
                attrs.add(it.previous());
            }

            res.put(key, attrs);
        }

        return res;
    }
}
