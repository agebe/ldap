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

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.google.common.net.HostAndPort;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchResultEntry;

public class LdapTest {

  private static Ldap ldap;

  @BeforeAll
  public static void setup() throws IOException {
    Path path = Files.writeString(Files.createTempFile("test-data", ".ldif"),
        IOUtils.toString(LdapTest.class.getResourceAsStream("/test-data.ldif"), StandardCharsets.UTF_8),
        StandardCharsets.UTF_8,
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING);
    path.toFile().deleteOnExit();
    Ldap.LdapOptions options = new Ldap.LdapOptions();
    options.ldifFile = path.toFile();
    options.authenticatedRequired = true;
    options.dmPassword = "password";
    options.ldapListen = HostAndPort.fromString("localhost:0");
    ldap = new Ldap();
    Runnable r = () -> {
      try {
        ldap.run(options);
      } catch(Exception e) {
        e.printStackTrace();
      }
    };
    Thread t = new Thread(r, "ldap-server");
    t.start();
    ldap.waitForStartupComplete();
  }

  @AfterAll
  public static void tearDown() {
    ldap.shutdown();
  }

  @Test
  public void test() throws Exception {
    System.out.println(InetAddress.getLocalHost().getHostAddress());
    try(LDAPConnection conn = ldap.getConnection()) {
    //try(LDAPConnection conn = ldap.getStartTLSConnection()) {
      try {
        conn.getEntry("uid=bob,ou=people,dc=springframework,dc=org");
        throw new RuntimeException("got search result but expected LDAPException as search should not be allowed for anonymous user");
      } catch(LDAPException e) {
        // expected
      }
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
      // no delete allowed
      //      conn.delete("uid=bob,ou=people,dc=springframework,dc=org");
      //      conn.bind("uid=bob,ou=people,dc=springframework,dc=org", "bobspassword");
    }
  }
}
