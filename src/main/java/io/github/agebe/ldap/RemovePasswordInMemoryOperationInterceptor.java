/*
 * Copyright 2021 Andre Gebers
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package io.github.agebe.ldap;

import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchEntry;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.SearchResultEntry;

public class RemovePasswordInMemoryOperationInterceptor extends InMemoryOperationInterceptor {

  @Override
  public void processSearchEntry(InMemoryInterceptedSearchEntry entry) {
    try {
      SearchResultEntry srentry = entry.getSearchEntry();
      if(srentry.hasAttribute("userPassword")) {
        SearchResultEntry copy = new SearchResultEntry(
            srentry.getDN(),
            srentry.getAttributes().stream()
            .filter(attr -> !"userPassword".equals(attr.getName()))
            .toArray(Attribute[]::new),
            srentry.getControls());
        entry.setSearchEntry(copy);
      }
    } catch(Exception e) {
      e.printStackTrace();
    }
  }

}
