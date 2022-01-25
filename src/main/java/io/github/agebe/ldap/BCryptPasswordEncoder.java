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

import java.util.List;

import org.mindrot.jbcrypt.BCrypt;

import com.unboundid.ldap.listener.InMemoryPasswordEncoder;
import com.unboundid.ldap.listener.PasswordEncoderOutputFormatter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;

public class BCryptPasswordEncoder extends InMemoryPasswordEncoder {

  // copied from https://en.wikipedia.org/wiki/Bcrypt
  private static final String BCRYPT_REGEX = "^[$]2[abxy]?[$](?:0[4-9]|[12][0-9]|3[01])[$][./0-9a-zA-Z]{53}$";

  protected BCryptPasswordEncoder(String prefix, PasswordEncoderOutputFormatter outputFormatter) {
    super(prefix, outputFormatter);
  }

  @Override
  protected byte[] encodePassword(byte[] clearPassword, ReadOnlyEntry userEntry, List<Modification> modifications)
      throws LDAPException {
    String p = new String(clearPassword);
    return p.matches(BCRYPT_REGEX)?clearPassword:BCrypt.hashpw(p, BCrypt.gensalt(10)).getBytes();
  }

  @Override
  protected void ensurePreEncodedPasswordAppearsValid(byte[] unPrefixedUnFormattedEncodedPasswordBytes,
      ReadOnlyEntry userEntry, List<Modification> modifications) throws LDAPException {
    // TODO Auto-generated method stub
    
  }

  @Override
  protected boolean passwordMatches(byte[] clearPasswordBytes, byte[] unPrefixedUnFormattedEncodedPasswordBytes,
      ReadOnlyEntry userEntry) throws LDAPException {
    return BCrypt.checkpw(new String(clearPasswordBytes), new String(unPrefixedUnFormattedEncodedPasswordBytes));
  }

  @Override
  protected byte[] extractClearPassword(byte[] unPrefixedUnFormattedEncodedPasswordBytes, ReadOnlyEntry userEntry)
      throws LDAPException {
    throw new LDAPException(ResultCode.OTHER, "password is not reversible");
  }

  @Override
  public void toString(StringBuilder buffer) {
    buffer.append(toString());
  }

}
