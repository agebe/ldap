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

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.google.common.net.HostAndPort;
import com.unboundid.ldap.listener.Base64PasswordEncoderOutputFormatter;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ssl.PEMFileKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;

public class Ldap {

  private static final Logger log = LoggerFactory.getLogger(Ldap.class);

  private static final int DEFAULT_LDAP_PORT = 389;
  private static final int DEFAULT_LDAPS_PORT = 636;

  public static class LdapOptions {

    @Parameter(names="--help", help=true, description="show usage")
    public boolean help;

    @Parameter(names="--base-dn", description="Base DN to use for the server. Auto detected from ldif file if not set")
    public String baseDn;

    @Parameter(names="--disable-schema", description="To allow any attribute in the ldif file")
    public boolean disableSchema;

    @Parameter(names="--auth-required", description="authentication required for search and compare")
    public boolean authenticatedRequired;

    @Parameter(description="path to ldif file to import", converter = com.beust.jcommander.converters.FileConverter.class)
    public File ldifFile;

    @Parameter(names="--log-level", description="logback log level (trace, debug, info, warn, error, all, off)."
        + " Configure multiple loggers separated by comma")
    public String logLevel = "root:info";

    @Parameter(names="--directory-manager", description="directory manager user account")
    public String dmUser = "Directory Manager";

    @Parameter(names="--directory-manager-password", description="directory manager password")
    public String dmPassword;

    @Parameter(names="--tls-cert", description="pem encoded cert file used for StartTLS and LDAPS",
        converter = com.beust.jcommander.converters.FileConverter.class)
    public File certFile;

    @Parameter(names="--tls-key", description="pem encoded key file used for StartTLS and LDAPS",
        converter = com.beust.jcommander.converters.FileConverter.class)
    public File keyFile;

    @Parameter(names="--ldap-listen", description="host:port of to listen for ldap connections",
        converter = HostAndPortConverter.class)
    public HostAndPort ldapListen = HostAndPort.fromString("localhost").withDefaultPort(DEFAULT_LDAP_PORT);

    @Parameter(names="--ldaps-listen", description="host:port of to listen for ldaps connections",
        converter = HostAndPortConverter.class)
    public HostAndPort ldapsListen = HostAndPort.fromString("localhost").withDefaultPort(DEFAULT_LDAPS_PORT);

  }

  private InMemoryDirectoryServer ds;

  private AtomicBoolean shutdown = new AtomicBoolean();

  private CompletableFuture<Boolean> startupComplete = new CompletableFuture<>();

  public static void main(String[] args) throws Exception {
    LdapOptions options = new LdapOptions();
    JCommander jcommander = JCommander.newBuilder().addObject(options).build();
    jcommander.setProgramName("ldap");
    jcommander.parse(args);
    if(options.help) {
      jcommander.usage();
      return;
    } else {
      new Ldap().run(options);
    }
  }

  public void run(LdapOptions options) throws Exception {
    setupLogLevels(options.logLevel);
    InMemoryDirectoryServerConfig config =
        new InMemoryDirectoryServerConfig(getBaseDn(options));
    config.setPasswordEncoders(new BCryptPasswordEncoder("bcrypt:", Base64PasswordEncoderOutputFormatter.getInstance()));
    config.addInMemoryOperationInterceptor(new RemovePasswordInMemoryOperationInterceptor());
    config.addInMemoryOperationInterceptor(new TraceLogOperations());
    config.addInMemoryOperationInterceptor(new BindLogger());
    if(StringUtils.isNotBlank(options.dmPassword)) {
      config.addAdditionalBindCredentials("cn="+options.dmUser, options.dmPassword);
    }
    if(options.disableSchema) {
      config.setSchema(null);
    }
    config.setAllowedOperationTypes(
        OperationType.ABANDON,
        OperationType.BIND,
        OperationType.COMPARE,
        OperationType.SEARCH,
        OperationType.UNBIND);
    if(options.authenticatedRequired) {
      config.setAuthenticationRequiredOperationTypes(OperationType.COMPARE, OperationType.SEARCH);
    }
    setupListeners(config, options);
    try(InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config)) {
      this.ds = ds;
      int entries = ds.importFromLDIF(true, options.ldifFile);
      log.info("imported '{}' entries from ldif file '{}'", entries, options.ldifFile.getAbsolutePath());
      ds.startListening();
      log.info("started listeners, ready for connections", entries);
      startupComplete.complete(true);
      waitForShutdown();
      log.info("shutting down");
      ds.shutDown(true);
    }
  }

  private void setupListeners(
      InMemoryDirectoryServerConfig config,
      LdapOptions options) throws LDAPException, GeneralSecurityException, UnknownHostException {
    SSLUtil serverSSLUtil = createServerSSLUtil(options);
    if(serverSSLUtil != null) {
      log.info("start ldap listener on '{}', port '{}'",
          options.ldapListen.getHost(),
          options.ldapListen.getPortOrDefault(DEFAULT_LDAP_PORT));
      log.info("start ldaps listener on '{}', port '{}'",
          options.ldapsListen.getHost(),
          options.ldapsListen.getPortOrDefault(DEFAULT_LDAPS_PORT));
      config.setListenerConfigs(
          InMemoryListenerConfig.createLDAPConfig("LDAP",
              InetAddress.getByName(options.ldapListen.getHost()), // Listen address. (null = listen on all interfaces)
              options.ldapListen.getPortOrDefault(DEFAULT_LDAP_PORT), // Listen port (0 = automatically choose an available port)
              serverSSLUtil.createSSLSocketFactory()), // StartTLS factory
          InMemoryListenerConfig.createLDAPSConfig("LDAPS", // Listener name
              InetAddress.getByName(options.ldapsListen.getHost()), // Listen address. (null = listen on all interfaces)
              options.ldapsListen.getPortOrDefault(DEFAULT_LDAPS_PORT), // Listen port (0 = automatically choose an available port)
              serverSSLUtil.createSSLServerSocketFactory(),
              null));
    } else {
      log.info("start ldap listener on '{}', port '{}'",
          options.ldapListen.getHost(),
          options.ldapListen.getPortOrDefault(DEFAULT_LDAP_PORT));
      config.setListenerConfigs(
          InMemoryListenerConfig.createLDAPConfig("LDAP",
              InetAddress.getByName(options.ldapListen.getHost()), // Listen address. (null = listen on all interfaces)
              options.ldapListen.getPortOrDefault(DEFAULT_LDAP_PORT), // Listen port (0 = automatically choose an available port)
              null));
    }
  }

  private SSLUtil createServerSSLUtil(LdapOptions options) throws KeyStoreException {
    if(options.certFile == null) {
      return null;
    }
    if(!options.certFile.isFile()) {
      return null;
    }
    if(options.keyFile == null) {
      return null;
    }
    if(!options.keyFile.isFile()) {
      return null;
    }
    SSLUtil serverSSLUtil = new SSLUtil(
        new PEMFileKeyManager(options.certFile, options.keyFile),
        new TrustAllTrustManager(false));
    return serverSSLUtil;
  }

  public LDAPConnection getConnection() throws LDAPException {
    //return new LDAPConnection("localhost", ds.getListenPort());
    return ds.getConnection("LDAP");
  }

  public LDAPConnection getStartTLSConnection() throws LDAPException, GeneralSecurityException {
    LDAPConnection connection = getConnection();
    SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager(false));
    connection.processExtendedOperation(new StartTLSExtendedRequest(clientSSLUtil.createSSLSocketFactory()));
    return connection;
  }

  public LDAPConnection getLdapsConnection() throws LDAPException {
    return ds.getConnection("LDAPS");
  }

  public void waitForStartupComplete() {
    try {
      startupComplete.get();
    } catch(Exception e) {
      throw new RuntimeException("failed to wait for startup complete", e);
    }
  }

  private synchronized void waitForShutdown() {
    for(;;) {
      if(this.shutdown.get()) {
        break;
      }
      try {
        this.wait();
      } catch (InterruptedException e) {
        // ignore
      }
    }
  }

  public synchronized void shutdown() {
    shutdown.set(true);
    this.notifyAll();
  }

  private String getBaseDn(LdapOptions options) throws IOException {
    if(StringUtils.isNotBlank(options.baseDn)) {
      return options.baseDn;
    } else {
      if(options.ldifFile == null) {
        return null;
      } else {
        File f = options.ldifFile;
        if(f.isFile()) {
          List<String> l = Files.readAllLines(options.ldifFile.toPath(), StandardCharsets.UTF_8);
          for(String s : l) {
            if(StringUtils.startsWith(s, "dn:")) {
              return StringUtils.strip(StringUtils.removeStart(s, "dn:"));
            }
          }
        }
      }
    }
    return null;
  }

  private static void setupLogLevels(String s) {
    Stream.of(StringUtils.split(s, ',')).forEachOrdered(l -> {
      String[] split = StringUtils.split(l, ':');
      if(split.length == 1) {
        setLogLevel("root", split[0]);
      } else {
        setLogLevel(split[0], split[1]);
      }
    });
  }

  public static void setLogLevel(String name, String level) {
    LoggerContext loggerContext = (LoggerContext)LoggerFactory.getILoggerFactory();
    Logger logger = loggerContext.getLogger(name);
    Level l = (StringUtils.isBlank(level) || StringUtils.equalsIgnoreCase("PARENT", level))?
        null:Level.valueOf(StringUtils.upperCase(level));
    ((ch.qos.logback.classic.Logger)logger).setLevel(l);
  }

}

// copied from the InMemoryDirectoryServer javadoc showing how to enable STARTTLS and LDAPS
// also look here https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/StartTLSPostConnectProcessor.html
/**
* <H2>Example</H2>
* The following example demonstrates the process that can be used to create,
* start, and use an in-memory directory server instance, including support for
* secure communication using both SSL and StartTLS:
* <PRE>
* // Create a base configuration for the server.
* InMemoryDirectoryServerConfig config =
*      new InMemoryDirectoryServerConfig("dc=example,dc=com");
* config.addAdditionalBindCredentials("cn=Directory Manager",
*      "password");
*
* // Update the configuration to support LDAP (with StartTLS) and LDAPS
* // listeners.
* final SSLUtil serverSSLUtil = new SSLUtil(
*      new KeyStoreKeyManager(serverKeyStorePath, serverKeyStorePIN, "JKS",
*           "server-cert"),
*      new TrustStoreTrustManager(serverTrustStorePath));
* final SSLUtil clientSSLUtil = new SSLUtil(
*      new TrustStoreTrustManager(clientTrustStorePath));
* config.setListenerConfigs(
*      InMemoryListenerConfig.createLDAPConfig("LDAP", // Listener name
*           null, // Listen address. (null = listen on all interfaces)
*           0, // Listen port (0 = automatically choose an available port)
*           serverSSLUtil.createSSLSocketFactory()), // StartTLS factory
*      InMemoryListenerConfig.createLDAPSConfig("LDAPS", // Listener name
*           null, // Listen address. (null = listen on all interfaces)
*           0, // Listen port (0 = automatically choose an available port)
*           serverSSLUtil.createSSLServerSocketFactory(), // Server factory
*           clientSSLUtil.createSSLSocketFactory())); // Client factory
*
* // Create and start the server instance and populate it with an initial set
* // of data from an LDIF file.
* InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);
* server.importFromLDIF(true, ldifFilePath);
*
* // Start the server so it will accept client connections.
* server.startListening();
*
* // Get an unencrypted connection to the server's LDAP listener, then use
* // StartTLS to secure that connection.  Make sure the connection is usable
* // by retrieving the server root DSE.
* LDAPConnection connection = server.getConnection("LDAP");
* connection.processExtendedOperation(new StartTLSExtendedRequest(
*      clientSSLUtil.createSSLContext()));
* LDAPTestUtils.assertEntryExists(connection, "");
* connection.close();
*
* // Establish an SSL-based connection to the LDAPS listener, and make sure
* // that connection is also usable.
* connection = server.getConnection("LDAPS");
* LDAPTestUtils.assertEntryExists(connection, "");
* connection.close();
*
* // Shut down the server so that it will no longer accept client
* // connections, and close all existing connections.
* server.shutDown(true);
* </PRE>
*/

