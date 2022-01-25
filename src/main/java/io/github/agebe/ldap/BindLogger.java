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

import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.ResultCode;

public class BindLogger extends InMemoryOperationInterceptor {

  private static final Logger log = LoggerFactory.getLogger(BindLogger.class);

  @Override
  public void processSimpleBindResult(InMemoryInterceptedSimpleBindResult result) {
    if(ResultCode.SUCCESS == result.getResult().getResultCode()) {
      log.info("bind success, '{}', '{}'", result.getRequest().getBindDN(), result.getConnectedAddress());
    } else {
      log.info("bind failed, '{}', '{}', '{}'",
          result.getRequest().getBindDN(),
          result.getConnectedAddress(),
          result.getResult().getDiagnosticMessage());
    }
  }

}
