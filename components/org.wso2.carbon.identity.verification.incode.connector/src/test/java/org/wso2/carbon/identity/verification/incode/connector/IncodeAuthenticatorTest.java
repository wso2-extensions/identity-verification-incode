/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.verification.incode.connector;

import org.mockito.MockedStatic;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerClientException;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerServerException;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.AssociatedIdentityProvider;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.FederatedAssociation;
import org.wso2.carbon.identity.verification.incode.connector.constants.ErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.incode.connector.internal.IncodeConnectorDataHolder;
import org.wso2.carbon.idp.mgt.IdpManager;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.fail;

public class IncodeAuthenticatorTest {

    private static final String IDENTITY_ID = "test-identity-id";
    private static final String TENANT = "carbon.super";
    private static final String ONBOARDING_CONNECTION = "Incode Onboarding";

    private final IncodeAuthenticator authenticator = new IncodeAuthenticator();
    private FederatedAssociationManager associationManager;
    private IdpManager idpManager;

    @BeforeMethod
    public void setUp() throws Exception {

        associationManager = mock(FederatedAssociationManager.class);
        idpManager = mock(IdpManager.class);
        IncodeConnectorDataHolder.setFederatedAssociationManager(associationManager);
        IncodeConnectorDataHolder.setIdpManager(idpManager);
        when(idpManager.getIdPByName(ONBOARDING_CONNECTION, TENANT)).thenReturn(connection("IncodeAuthenticator"));
        when(idpManager.getIdPByName("Google", TENANT)).thenReturn(connection("GoogleOIDCAuthenticator"));
    }

    @Test
    public void testNames() {

        assertEquals(authenticator.getName(), "IncodeAuthenticator");
        assertEquals(authenticator.getFriendlyName(), "Incode");
        assertFalse(authenticator.isAPIBasedAuthenticationSupported());
    }

    @Test
    public void testLoginHintIsTheIdentityLinkedByTheOnboardingConnection() throws Exception {

        AuthenticationContext context = context(localUser(), false);
        context.getAuthenticatorProperties().put(FrameworkConstants.QUERY_PARAMS, "prompt=login");
        FederatedAssociation[] associations = {association("Google", "google-subject"),
                association(ONBOARDING_CONNECTION, IDENTITY_ID)};
        when(associationManager.getFederatedAssociationsOfUser(any())).thenReturn(associations);

        assertNull(authenticator.addLinkedIdentityAsLoginHint(context));
        assertEquals(context.getAuthenticatorProperties().get(FrameworkConstants.QUERY_PARAMS),
                "prompt=login&login_hint=" + IDENTITY_ID);
        assertEquals(context.getProperty("incodeExpectedIdentity"), IDENTITY_ID);
    }

    @Test
    public void testLinkIsReadInTheUsersTenant() throws Exception {

        AuthenticatedUser user = localUser();
        user.setTenantDomain("tenant-b");
        when(idpManager.getIdPByName(ONBOARDING_CONNECTION, "tenant-b")).thenReturn(connection("IncodeAuthenticator"));
        FederatedAssociation[] associations = {association(ONBOARDING_CONNECTION, IDENTITY_ID)};
        when(associationManager.getFederatedAssociationsOfUser(any())).thenReturn(associations);

        assertNull(authenticator.addLinkedIdentityAsLoginHint(context(user, false)));
    }

    @Test
    public void testQueryStringWithLoginHintReplacesConfiguredPromptAndLoginHint() {

        assertEquals(IncodeAuthenticator.getQueryStringWithLoginHint(
                        "response_mode=form_post&login_hint=someone-else&prompt=none", IDENTITY_ID),
                "response_mode=form_post&prompt=login&login_hint=" + IDENTITY_ID);
        assertEquals(IncodeAuthenticator.getQueryStringWithLoginHint(null, IDENTITY_ID),
                "prompt=login&login_hint=" + IDENTITY_ID);
        assertEquals(IncodeAuthenticator.getQueryStringWithLoginHint("", "a&b=c"), "prompt=login&login_hint=a%26b%3Dc");
    }

    @Test
    public void testUserWithoutAnIncodeLinkIsNotLinked() throws Exception {

        FederatedAssociation[] associations = {association("Google", "google-subject")};
        when(associationManager.getFederatedAssociationsOfUser(any())).thenReturn(associations);

        assertEquals(authenticator.addLinkedIdentityAsLoginHint(context(localUser(), false)),
                ErrorMessage.IDENTITY_NOT_LINKED);
    }

    @Test
    public void testUnknownUserIsNotLinked() throws Exception {

        when(associationManager.getFederatedAssociationsOfUser(any()))
                .thenThrow(new FederatedAssociationManagerClientException("Invalid user identifier provided."));
        assertEquals(authenticator.addLinkedIdentityAsLoginHint(context(localUser(), false)),
                ErrorMessage.IDENTITY_NOT_LINKED);
    }

    @Test
    public void testAssociationLookupFailureIsAServerError() throws Exception {

        when(associationManager.getFederatedAssociationsOfUser(any()))
                .thenThrow(new FederatedAssociationManagerServerException("Database error."));
        assertEquals(authenticator.addLinkedIdentityAsLoginHint(context(localUser(), false)),
                ErrorMessage.RESOLVING_ASSOCIATION);
    }

    @Test
    public void testTheSubjectStepMustComeBeforeTheIncodeStep() {

        // Incode is step 1, the current step, and the password step after it is the subject step.
        StepConfig incodeStep = new StepConfig();
        StepConfig passwordStep = new StepConfig();
        passwordStep.setSubjectIdentifierStep(true);
        Map<Integer, StepConfig> steps = new HashMap<>();
        steps.put(1, incodeStep);
        steps.put(2, passwordStep);
        AuthenticationContext context = context(localUser(), false);
        context.getSequenceConfig().setStepMap(steps);
        context.setCurrentStep(1);

        assertEquals(authenticator.addLinkedIdentityAsLoginHint(context), ErrorMessage.INVALID_CONFIGURATION);
    }

    @Test
    public void testTheSubjectStepMustBeAnEarlierStepWithALocalUser() {

        assertEquals(authenticator.addLinkedIdentityAsLoginHint(context(localUser(), true)),
                ErrorMessage.INVALID_CONFIGURATION);
        assertEquals(authenticator.addLinkedIdentityAsLoginHint(context(null, false)), ErrorMessage.NO_LOCAL_USER);
        AuthenticatedUser federatedUser = localUser();
        federatedUser.setFederatedUser(true);
        assertEquals(authenticator.addLinkedIdentityAsLoginHint(context(federatedUser, false)),
                ErrorMessage.NO_LOCAL_USER);
    }

    @Test
    public void testRequestErrorsShowTheRetryPageWithI18nTokens() throws Exception {

        AuthenticationContext context = context(localUser(), false);
        when(associationManager.getFederatedAssociationsOfUser(any())).thenReturn(new FederatedAssociation[0]);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class)) {
            authenticator.initiateAuthenticationRequest(request, response, context);

            frameworkUtils.verify(() -> FrameworkUtils.sendToRetryPage(request, response, context,
                    "{{incode.identity.verification.not.linked.message}}",
                    "{{incode.identity.verification.not.linked.description}}"));
        }
        assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE), "INCODE-60001");
    }

    @Test
    public void testIncodeErrorsFailTheStepWithACode() {

        assertCallbackError("access_denied", "INCODE-60002");
        assertCallbackError("server_error", "INCODE-60005");
        assertCallbackError("expired_token", "INCODE-60005");
    }

    @Test
    public void testIncodeDenialGivesTheApplicationAGeneralMessage() {

        // Incode returns access_denied both for a cancel and for a face check that does not pass.
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("error")).thenReturn("access_denied");
        AuthenticationContext context = context(localUser(), false);
        try {
            authenticator.processAuthenticationResponse(request, mock(HttpServletResponse.class), context);
            fail("The step must fail when Incode denies the verification.");
        } catch (AuthenticationFailedException e) {
            assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_MSG),
                    "Identity verification was cancelled or not completed. Please try again.");
        }
    }

    @Test
    public void testIncodeMustReturnTheLinkedIdentityAndAPassingStatus() {

        Map<ClaimMapping, String> claims = new HashMap<>();
        claims.put(ClaimMapping.build("identity_id", "identity_id", null, false), IDENTITY_ID);
        assertEquals(IncodeAuthenticator.validateFaceAuthenticationResult(claims, IDENTITY_ID),
                ErrorMessage.VERIFICATION_FAILED, "A token without a status fails the step.");

        claims.put(ClaimMapping.build("auth_overall_status", "auth_overall_status", null, false), "PASS");
        assertNull(IncodeAuthenticator.validateFaceAuthenticationResult(claims, IDENTITY_ID));
        assertEquals(IncodeAuthenticator.validateFaceAuthenticationResult(claims, "another-identity"),
                ErrorMessage.LOGIN_IDENTITY_MISMATCH);
        assertEquals(IncodeAuthenticator.validateFaceAuthenticationResult(claims, null),
                ErrorMessage.LOGIN_IDENTITY_MISMATCH);
        claims.put(ClaimMapping.build("auth_overall_status", "auth_overall_status", null, false), "FAIL");
        assertEquals(IncodeAuthenticator.validateFaceAuthenticationResult(claims, IDENTITY_ID),
                ErrorMessage.VERIFICATION_FAILED);
    }

    private void assertCallbackError(String oauthError, String expectedCode) {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("error")).thenReturn(oauthError);
        AuthenticationContext context = context(localUser(), false);
        try {
            authenticator.processAuthenticationResponse(request, mock(HttpServletResponse.class), context);
            fail("The step must fail when Incode returns an error.");
        } catch (AuthenticationFailedException e) {
            assertEquals(e.getErrorCode(), expectedCode);
            assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE), expectedCode);
        }
    }

    /**
     * Step 1 is the password step and step 2, the current one, is Incode.
     */
    private static AuthenticationContext context(AuthenticatedUser stepOneUser, boolean incodeIsTheSubjectStep) {

        StepConfig passwordStep = new StepConfig();
        passwordStep.setSubjectIdentifierStep(!incodeIsTheSubjectStep);
        passwordStep.setAuthenticatedUser(stepOneUser);
        StepConfig incodeStep = new StepConfig();
        incodeStep.setSubjectIdentifierStep(incodeIsTheSubjectStep);
        Map<Integer, StepConfig> steps = new HashMap<>();
        steps.put(1, passwordStep);
        steps.put(2, incodeStep);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(steps);

        AuthenticationContext context = new AuthenticationContext();
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(2);
        context.setTenantDomain(TENANT);
        context.setAuthenticatorProperties(new HashMap<>());
        return context;
    }

    private static AuthenticatedUser localUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("alice");
        user.setUserStoreDomain("PRIMARY");
        user.setTenantDomain(TENANT);
        return user;
    }

    private static FederatedAssociation association(String connectionName, String federatedUserId) {

        AssociatedIdentityProvider idp = mock(AssociatedIdentityProvider.class);
        when(idp.getName()).thenReturn(connectionName);
        FederatedAssociation association = mock(FederatedAssociation.class);
        when(association.getIdp()).thenReturn(idp);
        when(association.getFederatedUserId()).thenReturn(federatedUserId);
        return association;
    }

    private static IdentityProvider connection(String authenticatorName) {

        FederatedAuthenticatorConfig authenticator = new FederatedAuthenticatorConfig();
        authenticator.setName(authenticatorName);
        IdentityProvider idp = new IdentityProvider();
        idp.setDefaultAuthenticatorConfig(authenticator);
        return idp;
    }
}
