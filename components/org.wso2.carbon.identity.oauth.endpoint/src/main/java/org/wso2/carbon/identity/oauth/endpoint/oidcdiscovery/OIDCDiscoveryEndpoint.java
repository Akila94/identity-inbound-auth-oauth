/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.oidcdiscovery;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDCProcessor;
import org.wso2.carbon.identity.discovery.builders.OIDProviderResponseBuilder;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.oidcdiscovery.impl.OIDProviderJSONResponseBuilder;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

@Path("/{discoveryEpPathComponent}/.well-known/openid-configuration")
public class OIDCDiscoveryEndpoint {

    private static final Log log = LogFactory.getLog(OIDCDiscoveryEndpoint.class);
    private static final String TOKEN_ENDPOINT_VALUE_TOKEN = "token";
    private static final String TOKEN_ENDPOINT_VALUE_OIDCDISCOVERY = "oidcdiscovery";

    @GET
    @Produces("application/json")
    public Response getOIDProviderConfiguration(
            @PathParam("discoveryEpPathComponent") String tokenEp, @Context HttpServletRequest request) {

        String tenantDomain = null;
        Object tenantObj = IdentityUtil.threadLocalProperties.get().get(OAuthConstants.TENANT_NAME_FROM_CONTEXT);
        if (tenantObj != null) {
            tenantDomain = (String) tenantObj;
        }
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        if (isValidIssuer(tokenEp)) {
            return this.getResponse(request, tenantDomain);
        } else {
            Response.ResponseBuilder errorResponse = Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            if(log.isDebugEnabled()) {
                log.debug("The provided token endpoint is " + tokenEp + " . The expected token token endpoint is either '"
                        + TOKEN_ENDPOINT_VALUE_TOKEN + "' or '" + TOKEN_ENDPOINT_VALUE_OIDCDISCOVERY );
            }
            return errorResponse.entity("Error while loading the endpoint. Invalid path to the discovery document. " +
                    "The expected token endpoint is either '" + TOKEN_ENDPOINT_VALUE_TOKEN + "' or '"
                    + TOKEN_ENDPOINT_VALUE_OIDCDISCOVERY + "' but " + "received: " + tokenEp)
                    .build();
        }
    }

    private boolean isValidIssuer(String discoveryEpPathComponent) {

        if (TOKEN_ENDPOINT_VALUE_TOKEN.equals(discoveryEpPathComponent) || TOKEN_ENDPOINT_VALUE_OIDCDISCOVERY.equals(discoveryEpPathComponent)) {
            return true;
        }
        if (log.isDebugEnabled()) {
            log.debug("Token endpoint validation failed. Token endpoint value: " + discoveryEpPathComponent + ", not matched to '"
                    + TOKEN_ENDPOINT_VALUE_TOKEN + "' or '" + TOKEN_ENDPOINT_VALUE_OIDCDISCOVERY + "'");
        }
        return false;
    }

    private Response getResponse(HttpServletRequest request, String tenant) {

        String response;
        OIDCProcessor processor = EndpointUtil.getOIDCService();
        try {
            OIDProviderResponseBuilder responseBuilder = new OIDProviderJSONResponseBuilder();
            response = responseBuilder.getOIDProviderConfigString(processor.getResponse(request, tenant));
        } catch (OIDCDiscoveryEndPointException e) {
            Response.ResponseBuilder errorResponse = Response.status(processor.handleError(e));
            return errorResponse.entity(e.getMessage()).build();
        } catch (ServerConfigurationException e) {
            log.error("Server Configuration error occurred.", e);
            Response.ResponseBuilder errorResponse = Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return errorResponse.entity("Error in reading configuration.").build();
        }
        Response.ResponseBuilder responseBuilder = Response.status(HttpServletResponse.SC_OK);
        return responseBuilder.entity(response).build();
    }
}
