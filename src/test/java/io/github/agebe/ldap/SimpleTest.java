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

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;

public class SimpleTest {

  private static void test(LDAPConnection conn) throws Exception {
    conn.bind("cn=Directory Manager", "password");
    SearchResultEntry entry = conn.getEntry("uid=bob,ou=people,dc=springframework,dc=org");
    System.out.println("search result: " + entry);
    System.out.println(conn.compare("uid=bob,ou=people,dc=springframework,dc=org", "userPassword", "bobspassword"));
    System.out.println(conn.compare("uid=bob,ou=people,dc=springframework,dc=org", "uid", "bob"));
    conn.bind("uid=bob,ou=people,dc=springframework,dc=org", "bobspassword");
    conn.bind("uid=ben,ou=people,dc=springframework,dc=org", "benspassword");
    try {
      conn.bind("uid=bob,ou=people,dc=springframework,dc=org", "wrong-password");
    } catch(Exception e) {
      // exception expected and ignored
    }
  }

  public static void main(String[] args) throws Exception {
    try(LDAPConnection con = new LDAPConnection("localhost", 1389)) {
      SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager(false));
      con.processExtendedOperation(new StartTLSExtendedRequest(clientSSLUtil.createSSLSocketFactory()));
      test(con);
    }
  }
}
