/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;

import java.util.Scanner;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;

@PrepareForTest(UserInforRequestDefaultValidator.class)
public class UserInfoISAccessTokenValidatorTest extends PowerMockTestCase {

    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private Scanner scanner;

    private UserInforRequestDefaultValidator userInforRequestDefaultValidator;
    private final String ACCESS_TOKEN = "ZWx1c3VhcmlvOnlsYWNsYXZl";
    private final String AUTHORIZATION_HEADER_VALUE = "Bearer " + ACCESS_TOKEN;
    private static String ALLOWED_CONTENT_TYPE_HEADER_VALUE = "application/x-www-form-urlencoded";

    @BeforeClass
    public void setup() {
        userInforRequestDefaultValidator = new UserInforRequestDefaultValidator();
    }

    @DataProvider
    public Object[][] getValidUserInfoInput() {

        return new Object[][]{
                {AUTHORIZATION_HEADER_VALUE, null, null, HttpMethod.GET, null},
                {AUTHORIZATION_HEADER_VALUE, null, null, HttpMethod.POST, null},
                {null, ACCESS_TOKEN, null, HttpMethod.GET, null},
                {null, ACCESS_TOKEN, null, HttpMethod.POST, null},
                {null, null, "access_token=" + ACCESS_TOKEN, HttpMethod.POST, ALLOWED_CONTENT_TYPE_HEADER_VALUE},
                {null, null, "xyz=abc&access_token=" + ACCESS_TOKEN + "&abc=yyy", HttpMethod.POST,
                        ALLOWED_CONTENT_TYPE_HEADER_VALUE},
                {null, null, "xyz=abc&access_token=" + ACCESS_TOKEN, HttpMethod.POST, ALLOWED_CONTENT_TYPE_HEADER_VALUE}
        };
    }

    @Test(dataProvider = "getValidUserInfoInput")
    public void testValidateToken(String authzHeaderValue,
                                  String accessTokenInRequestBody,
                                  String requestBody,
                                  String httpMethod,
                                  String contentType) throws Exception {

        prepareHttpServletRequest(authzHeaderValue, accessTokenInRequestBody, httpMethod, contentType);

        whenNew(Scanner.class).withAnyArguments().thenReturn(scanner);
        when(scanner.hasNextLine()).thenReturn(true, false);
        when(scanner.nextLine()).thenReturn(requestBody);

        assertEquals(userInforRequestDefaultValidator.validateRequest(httpServletRequest), ACCESS_TOKEN);
    }

    @DataProvider
    public Object[][] getInvalidAuthorizations() {

        return new Object[][]{
                {ACCESS_TOKEN, null, null},
                {"Bearer", null, null},
                {"Bearer       ", null, null},
                {"Basic " + ACCESS_TOKEN, null, null},
                {null, null, null},
                {null, "", null},
                {"", "", ""}
        };
    }

    @Test(dataProvider = "getInvalidAuthorizations", expectedExceptions = UserInfoEndpointException.class)
    public void testValidateTokenInvalidAuthorization(String authorizationHeaderValue,
                                                      String accessTokenInRequestBody,
                                                      String requestBody) throws Exception {

        prepareHttpServletRequest(authorizationHeaderValue, accessTokenInRequestBody);

        whenNew(Scanner.class).withAnyArguments().thenReturn(scanner);
        when(scanner.hasNextLine()).thenReturn(true, false);
        when(scanner.nextLine()).thenReturn(requestBody);

        userInforRequestDefaultValidator.validateRequest(httpServletRequest);
    }

    @DataProvider
    public Object[][] getInvalidRequestBodyContent() {

        return new Object[][]{
                {"access_token=" + ACCESS_TOKEN, HttpMethod.GET, ALLOWED_CONTENT_TYPE_HEADER_VALUE},
                {"access_token=" + ACCESS_TOKEN, HttpMethod.POST, null},
                {"access_token=" + ACCESS_TOKEN, HttpMethod.POST, ""},
                {"access_token=" + ACCESS_TOKEN, HttpMethod.POST, "application/json"}
        };
    }


    @Test(dataProvider = "getInvalidRequestBodyContent", expectedExceptions = UserInfoEndpointException.class)
    public void testInvalidRequestsWithTokenInRequestBody(String requestBody,
                                                          String httpMethod,
                                                          String contentType) throws Exception {

        whenNew(Scanner.class).withAnyArguments().thenReturn(scanner);
        when(scanner.hasNextLine()).thenReturn(true, false);
        when(scanner.nextLine()).thenReturn(requestBody);

        when(httpServletRequest.getMethod()).thenReturn(httpMethod);
        when(httpServletRequest.getContentType()).thenReturn(contentType);

        userInforRequestDefaultValidator.validateRequest(httpServletRequest);
    }


    private void prepareHttpServletRequest(String authorizationHeaderValue,
                                           String accessTokenInRequestBody,
                                           String httpMethod,
                                           String contentType) {

        when(httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authorizationHeaderValue);
        when(httpServletRequest.getParameter("access_token")).thenReturn(accessTokenInRequestBody);
        when(httpServletRequest.getMethod()).thenReturn(httpMethod);
        when(httpServletRequest.getContentType()).thenReturn(contentType);
    }

    private void prepareHttpServletRequest(String authorizationHeaderValue,
                                           String accessTokenInRequestBody) {

        when(httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authorizationHeaderValue);
        when(httpServletRequest.getParameter("access_token")).thenReturn(accessTokenInRequestBody);
    }
}
