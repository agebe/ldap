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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedAddRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedAddResult;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedCompareRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedCompareResult;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedDeleteRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedDeleteResult;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedExtendedRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedExtendedResult;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedIntermediateResponse;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedModifyDNRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedModifyDNResult;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedModifyRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedModifyResult;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSASLBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSASLBindResult;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchEntry;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchReference;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.LDAPException;

public class TraceLogOperations extends InMemoryOperationInterceptor {

  private static final Logger log = LoggerFactory.getLogger(TraceLogOperations.class);

  @Override
  public void processAddRequest(InMemoryInterceptedAddRequest request) throws LDAPException {
    log.trace("processAddRequest '{}'", request);
  }

  @Override
  public void processAddResult(InMemoryInterceptedAddResult result) {
    log.trace("processAddResult '{}'", result);
  }

  @Override
  public void processCompareRequest(InMemoryInterceptedCompareRequest request) throws LDAPException {
    log.trace("processCompareRequest '{}'", request);
  }

  @Override
  public void processCompareResult(InMemoryInterceptedCompareResult result) {
    log.trace("processCompareResult '{}'", result);
  }

  @Override
  public void processDeleteRequest(InMemoryInterceptedDeleteRequest request) throws LDAPException {
    log.trace("processDeleteRequest '{}'", request);
  }

  @Override
  public void processDeleteResult(InMemoryInterceptedDeleteResult result) {
    log.trace("processDeleteResult '{}'", result);
  }

  @Override
  public void processModifyRequest(InMemoryInterceptedModifyRequest request) throws LDAPException {
    log.trace("processModifyRequest '{}'", request);
  }

  @Override
  public void processModifyResult(InMemoryInterceptedModifyResult result) {
    log.trace("processModifyResult '{}'", result);
  }

  @Override
  public void processModifyDNRequest(InMemoryInterceptedModifyDNRequest request) throws LDAPException {
    log.trace("processModifyDNRequest '{}'", request);
  }

  @Override
  public void processModifyDNResult(InMemoryInterceptedModifyDNResult result) {
    log.trace("processModifyDNResult '{}'", result);
  }

  @Override
  public void processSearchRequest(InMemoryInterceptedSearchRequest request) throws LDAPException {
    log.trace("processSearchRequest '{}'", request);
  }

  @Override
  public void processSearchEntry(InMemoryInterceptedSearchEntry entry) {
    log.trace("processSearchEntry '{}'", entry);
  }

  @Override
  public void processSearchReference(InMemoryInterceptedSearchReference reference) {
    log.trace("processSearchReference '{}'", reference);
  }

  @Override
  public void processSearchResult(InMemoryInterceptedSearchResult result) {
    log.trace("processSearchResult '{}'", result);
  }

  @Override
  public void processIntermediateResponse(InMemoryInterceptedIntermediateResponse response) {
    log.trace("processIntermediateResponse '{}'", response);
  }

  @Override
  public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) throws LDAPException {
    log.trace("processSimpleBindRequest '{}'", request);
  }

  @Override
  public void processSASLBindRequest(InMemoryInterceptedSASLBindRequest request) throws LDAPException {
    log.trace("processSASLBindRequest '{}'", request);
  }

  @Override
  public void processSASLBindResult(InMemoryInterceptedSASLBindResult result) {
    log.trace("processSASLBindResult '{}'", result);
  }

  @Override
  public void processExtendedRequest(InMemoryInterceptedExtendedRequest request) throws LDAPException {
    log.trace("processExtendedRequest '{}'", request);
  }

  @Override
  public void processExtendedResult(InMemoryInterceptedExtendedResult result) {
    log.trace("processExtendedResult '{}'", result);
  }

  @Override
  public void processSimpleBindResult(InMemoryInterceptedSimpleBindResult result) {
    log.trace("processSimpleBindResult '{}'", result);
  }

}
