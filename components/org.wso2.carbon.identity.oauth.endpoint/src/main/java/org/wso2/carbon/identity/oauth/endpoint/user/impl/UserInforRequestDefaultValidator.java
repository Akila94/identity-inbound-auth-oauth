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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoRequestValidator;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.Scanner;

import static javax.ws.rs.HttpMethod.POST;

/**
 * Validates the schema and authorization header according to the specification
 *
 * @see http://openid.net/specs/openid-connect-basic-1_0-22.html#anchor6
 */
public class UserInforRequestDefaultValidator implements UserInfoRequestValidator {

    private static String US_ASCII = "US-ASCII";
    private static final String ACCESS_TOKEN_PARAM = "access_token";
    private static final String ACCESS_TOKEN_PARAM_DELIMITER = ACCESS_TOKEN_PARAM + "=";
    private static final String BEARER = "Bearer";
    private static String ALLOWED_CONTENT_TYPE_HEADER_VALUE = "application/x-www-form-urlencoded";

    @Override
    public String validateRequest(HttpServletRequest request) throws UserInfoEndpointException {

        String authorizationHeaderValue = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.isNotBlank(authorizationHeaderValue)) {
            // If Authorization header is present we try to retrieve the access token from it.
            return getAccessTokenFromAuthorizationHeader(authorizationHeaderValue);
        }

        String accessToken = getAccessTokenFromRequest(request);
        if (StringUtils.isNotBlank(accessToken)) {
            // Access token has been sent in the request body.
            return accessToken;
        }

        throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST, "Access token missing in " +
                "UserInfo request.");
    }

    private String getAccessTokenFromRequest(HttpServletRequest request) throws UserInfoEndpointException {

        // When request is sent through some valves such as RequestCorrelationIdValve, then Servlet Request's POST
        // body form params are set as request parameters.
        if (StringUtils.isNotBlank(request.getParameter(ACCESS_TOKEN_PARAM))) {
            return request.getParameter(ACCESS_TOKEN_PARAM);
        } else {
            // Otherwise need to read the POST body explicitly to extract the access_token.
            if (POST.equals(request.getMethod())) {
                return getAccessTokenFromRequestBody(request);
            } else {
                // We cannot proceed if the request is not POST
                return null;
            }
        }
    }

    private String getAccessTokenFromAuthorizationHeader(String authzHeaderValue) throws UserInfoEndpointException {

        // We expect the authorization header to be sent in the form "Bearer <access_token>".
        String[] authzHeaderInfo = authzHeaderValue.trim().split("\\s+");

        if (isNotBearerAuthorizationType(authzHeaderInfo) || isAccessTokenEmptyInAuthzHeader(authzHeaderInfo)) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST, "Bearer token missing");
        }

        return authzHeaderInfo[1];
    }

    private boolean isAccessTokenEmptyInAuthzHeader(String[] authzHeaderInfo) {

        return authzHeaderInfo.length < 2 || StringUtils.isBlank(authzHeaderInfo[1]);
    }

    private boolean isNotBearerAuthorizationType(String[] authzHeaderInfo) {

        return !BEARER.equals(authzHeaderInfo[0]);
    }


    public static boolean isPureAscii(String requestBody) {

        byte[] bytearray = requestBody.getBytes();
        CharsetDecoder charsetDecoder = Charset.forName(US_ASCII).newDecoder();
        try {
            CharBuffer charBuffer = charsetDecoder.decode(ByteBuffer.wrap(bytearray));
            charBuffer.toString();
        } catch (CharacterCodingException e) {
            return false;
        }
        return true;
    }

    private String getAccessTokenFromRequestBody(HttpServletRequest request) throws UserInfoEndpointException {

        // Validate the content-type
        validateContentType(request);

        StringBuilder stringBuilder = new StringBuilder();
        Scanner scanner = null;
        try {
            scanner = new Scanner(request.getInputStream());
        } catch (IOException e) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                    "Cannot read the request body to extract the access token.");
        }
        while (scanner.hasNextLine()) {
            stringBuilder.append(scanner.nextLine());
        }
        String[] arrAccessToken = new String[2];
        String requestBody = stringBuilder.toString();
        String[] arrAccessTokenNew;
        // To check whether the entity-body consist entirely of ASCII [USASCII] characters
        if (!isPureAscii(requestBody)) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                    "Request body contains non ASCII characters.");
        }

        if (requestBody.contains(ACCESS_TOKEN_PARAM_DELIMITER)) {
            arrAccessToken = requestBody.trim().split(ACCESS_TOKEN_PARAM_DELIMITER);
            if (arrAccessToken[1].contains("&")) {
                arrAccessTokenNew = arrAccessToken[1].split("&", 2);
                return arrAccessTokenNew[0];
            }
        }
        return arrAccessToken[1];
    }

    private void validateContentType(HttpServletRequest request) throws UserInfoEndpointException {

        String contentType = request.getContentType();
        if (StringUtils.isEmpty(contentType)) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                    "Content-Type header is missing.");
        }

        if (!StringUtils.equals(ALLOWED_CONTENT_TYPE_HEADER_VALUE, contentType)) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                    "Content-Type does not match the allowed type: " + ALLOWED_CONTENT_TYPE_HEADER_VALUE);
        }
    }
}
