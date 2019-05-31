/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.authz.handlers;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.callback.OAuthCallback;
import org.wso2.carbon.identity.oauth.callback.OAuthCallbackManager;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * AbstractResponseTypeHandler contains all the common methods of all three basic handlers.
 */
public abstract class AbstractResponseTypeHandler implements ResponseTypeHandler {

    private static Log log = LogFactory.getLog(AbstractResponseTypeHandler.class);

    public static final String IMPLICIT = "implicit";
    protected OauthTokenIssuer oauthIssuerImpl;
    protected boolean cacheEnabled;
    protected OAuthCache oauthCache;
    private OAuthCallbackManager callbackManager;

    @Override
    public void init() throws IdentityOAuth2Exception {
        callbackManager = new OAuthCallbackManager();
        oauthIssuerImpl = OAuthServerConfiguration.getInstance().getIdentityOauthTokenIssuer();
        cacheEnabled = OAuthCache.getInstance().isEnabled();
        if (cacheEnabled) {
            oauthCache = OAuthCache.getInstance();
        }
    }

    @Override
    public boolean validateAccessDelegation(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        OAuthCallback authzCallback = new OAuthCallback(authorizationReqDTO.getUser(),
                authorizationReqDTO.getConsumerKey(), OAuthCallback.OAuthCallbackType.ACCESS_DELEGATION_AUTHZ);
        authzCallback.setRequestedScope(authorizationReqDTO.getScopes());
        authzCallback.setResponseType(authorizationReqDTO.getResponseType());
        callbackManager.handleCallback(authzCallback);

        oauthAuthzMsgCtx.setValidityPeriod(authzCallback.getValidityPeriod());
        oauthAuthzMsgCtx.setAuthorizationCodeValidityPeriod(authzCallback.getAuthorizationCodeValidityPeriod());
        oauthAuthzMsgCtx.setAccessTokenIssuedTime(authzCallback.getAccessTokenValidityPeriod());
        return authzCallback.isAuthorized();
    }

    @Override
    public boolean validateScope(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        if (!validateByApplicationScopeValidator(oauthAuthzMsgCtx)) {
            return false;
        }

        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        OAuthCallback scopeValidationCallback = new OAuthCallback(authorizationReqDTO.getUser(),
                authorizationReqDTO.getConsumerKey(), OAuthCallback.OAuthCallbackType.SCOPE_VALIDATION_AUTHZ);
        scopeValidationCallback.setRequestedScope(authorizationReqDTO.getScopes());
        scopeValidationCallback.setResponseType(authorizationReqDTO.getResponseType());

        callbackManager.handleCallback(scopeValidationCallback);

        oauthAuthzMsgCtx.setValidityPeriod(scopeValidationCallback.getValidityPeriod());
        oauthAuthzMsgCtx.setAuthorizationCodeValidityPeriod(scopeValidationCallback
                .getAuthorizationCodeValidityPeriod());
        oauthAuthzMsgCtx.setAccessTokenIssuedTime(scopeValidationCallback.getAccessTokenValidityPeriod());
        oauthAuthzMsgCtx.setApprovedScope(scopeValidationCallback.getApprovedScope());
        return scopeValidationCallback.isValidScope();
    }

    @Override
    public boolean isAuthorizedClient(OAuthAuthzReqMessageContext authzReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authzReqDTO = authzReqMsgCtx.getAuthorizationReqDTO();
        String consumerKey = authzReqDTO.getConsumerKey();

        OAuthAppDO oAuthAppDO = (OAuthAppDO) authzReqMsgCtx.getProperty("OAuthAppDO");
        if (StringUtils.isBlank(oAuthAppDO.getGrantTypes())) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find authorized grant types for client id: " + consumerKey);
            }
            return false;
        }

        List<String> grantTypes = new ArrayList();

        String responseType = authzReqDTO.getResponseType();

        if (StringUtils.contains(responseType, ResponseType.CODE.toString())) {
            grantTypes.add(GrantType.AUTHORIZATION_CODE.toString());
        }

        if (OAuth2Util.isImplicitResponseType(responseType)) {
            grantTypes.add(OAuthConstants.GrantTypes.IMPLICIT.toString());
        }

        for (String grantType : grantTypes) {
            // If the application has defined a limited set of grant types, then check the grant
            if (!oAuthAppDO.getGrantTypes().contains(grantType)) {
                if (log.isDebugEnabled()) {
                    //Do not change this log format as these logs use by external applications
                    log.debug("Unsupported Grant Type : " + grantType + " for client id : " + consumerKey);
                }
                return false;
            }
        }

        return true;
    }

    /**
     * This method initialize OAuth2AuthoriseRespDTO object and set callbackURL and scope. This is common for all
     * response types.
     * @param oauthAuthzMsgCtx
     * @return OAUth2AuthorizeRespDTO object.
     * @throws IdentityOAuth2Exception
     */
    public OAuth2AuthorizeRespDTO initResponse(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {
        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        respDTO.setCallbackURI(authorizationReqDTO.getCallbackUrl());
        respDTO.setScope(oauthAuthzMsgCtx.getApprovedScope());
        return respDTO;
    }

    private boolean validateByApplicationScopeValidator(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        String[] scopeValidators;
        OAuthAppDO oAuthAppDO = (OAuthAppDO) authzReqMessageContext.getProperty("OAuthAppDO");

        if (oAuthAppDO == null) {
            try {
                oAuthAppDO = OAuth2Util.getAppInformationByClientId(
                        authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey());
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Error while retrieving OAuth application from DB for client id: " +
                        authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey(), e);
            }
        }

        scopeValidators = oAuthAppDO.getScopeValidators();

        if (ArrayUtils.isEmpty(scopeValidators)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("There is no scope validator registered for %s@%s",
                        oAuthAppDO.getApplicationName(), OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)));
            }
            return true;
        }

        ArrayList<String> appScopeValidators = new ArrayList<>(Arrays.asList(scopeValidators));
        // Return false only if iterateOAuth2ScopeValidators returned false. One more validation to do if it was true.
        if (!Oauth2ScopeUtils.iterateOAuth2ScopeValidators(authzReqMessageContext, null, appScopeValidators)) {
            return false;
        }

        if (!appScopeValidators.isEmpty()) {
            throw new IdentityOAuth2Exception(String.format("The scope validators %s registered for application %s@%s" +
                            " are not found in the server configuration ", StringUtils.join(appScopeValidators, ", "),
                    oAuthAppDO.getApplicationName(), OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)));
        }
        return true;
    }
}
