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
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.metadata.FlowExecutorMetadata;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.AssociatedIdentityProvider;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.FederatedAssociation;
import org.wso2.carbon.identity.verification.incode.connector.internal.IncodeConnectorDataHolder;
import org.wso2.carbon.idp.mgt.IdpManager;

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.OAuth2.SCOPES;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.REDIRECT_URL;

public class IncodeExecutorTest {

    private static final String IDENTITY_ID = "test-identity-id";
    private static final String TENANT = "carbon.super";
    private static final String CONNECTION = "Incode Onboarding";
    private static final String USERNAME_CLAIM = "http://wso2.org/claims/username";

    private final IncodeExecutor executor = new IncodeExecutor();
    private FederatedAssociationManager associationManager;
    private IdpManager idpManager;

    @BeforeMethod
    public void setUp() {

        associationManager = mock(FederatedAssociationManager.class);
        idpManager = mock(IdpManager.class);
        IncodeConnectorDataHolder.setFederatedAssociationManager(associationManager);
        IncodeConnectorDataHolder.setIdpManager(idpManager);
    }

    @Test
    public void testNameAndAmr() {

        assertEquals(executor.getName(), "IncodeExecutor");
        assertEquals(executor.getAMRValue(), "IncodeAuthenticator");
    }

    @Test
    public void testRegistrationStepMetadata() {

        assertEquals(executor.getSupportedFlowTypes(), EnumSet.of(FlowTypes.REGISTRATION,
                FlowTypes.INVITED_USER_REGISTRATION, FlowTypes.PASSWORD_RECOVERY));
        FlowExecutorMetadata metadata = executor.getExecutorMetadata();
        assertEquals(metadata.getDisplayName(), "Incode");
        assertEquals(metadata.getAssociatedAuthenticator(), "IncodeAuthenticator");
        assertEquals(metadata.getIcon(), "assets/images/icons/incode.svg");
        assertTrue(metadata.isConnectionRequired());
        assertTrue(metadata.isExternalClaimResolutionEnabled());
    }

    @Test
    public void testIncodeErrorEndsTheStepWithACode() {

        ExecutorResponse cancelled = executor.execute(context(Collections.singletonMap("error", "access_denied")));
        assertEquals(cancelled.getResult(), "USER_ERROR");
        assertEquals(cancelled.getErrorCode(), "INCODE-60002");
        assertEquals(cancelled.getErrorMessage(), "{{incode.identity.verification.cancelled.message}}");
        assertEquals(cancelled.getErrorDescription(), "{{incode.identity.verification.cancelled.description}}");

        ExecutorResponse failed = executor.execute(context(Collections.singletonMap("error", "server_error")));
        assertEquals(failed.getErrorCode(), "INCODE-60005");
    }

    @Test
    public void testStateMustMatch() {

        FlowExecutionContext context = context(callback("another-state"));
        context.setProperty("state", "state-sent");
        assertEquals(executor.execute(context).getErrorCode(), "INCODE-60007");
    }

    @Test
    public void testCallbackWithoutAStoredStateIsRefused() {

        assertEquals(executor.execute(context(callback("null"))).getErrorCode(), "INCODE-60007");
    }

    @Test
    public void testCallbackKeepsIncodeErrorCodes() throws Exception {

        FlowExecutionContext context = callbackContext();

        ExecutorResponse alreadyLinked = exchangeEndingWith(
                new FlowEngineClientException("INCODE-60009", "{{message}}", "{{description}}")).execute(context);
        assertEquals(alreadyLinked.getResult(), "USER_ERROR");
        assertEquals(alreadyLinked.getErrorCode(), "INCODE-60009");
        assertEquals(alreadyLinked.getErrorMessage(), "{{message}}");

        ExecutorResponse failed = exchangeEndingWith(
                new FlowEngineServerException("FE-65013", "Executor failure", "Token request failed")).execute(context);
        assertEquals(failed.getResult(), "ERROR");
        assertEquals(failed.getErrorCode(), "INCODE-65004");
        assertEquals(failed.getErrorMessage(), "{{incode.identity.verification.not.completed.message}}");

        Map<String, Object> claims = Collections.singletonMap("http://wso2.org/claims/incodeIdentityId", IDENTITY_ID);
        ExecutorResponse completed = exchangeEndingWith(claims).execute(context);
        assertEquals(completed.getResult(), "COMPLETE");
        assertEquals(completed.getUpdatedUserClaims(), claims);
    }

    /**
     * An executor whose token exchange with Incode returns the given claims or throws the given exception.
     */
    private static IncodeExecutor exchangeEndingWith(Object result) {

        return new IncodeExecutor() {
            @Override
            @SuppressWarnings("unchecked")
            protected Map<String, Object> resolveUserAttributes(FlowExecutionContext context, String code)
                    throws FlowEngineException {

                if (result instanceof FlowEngineException) {
                    throw (FlowEngineException) result;
                }
                return (Map<String, Object>) result;
            }
        };
    }

    @Test
    public void testOnlyAPassingNewIdentityCanSignUp() throws Exception {

        FlowExecutionContext context = context(Collections.emptyMap());
        assertEquals(executor.validateOnboardingResult(context, idToken(IDENTITY_ID, "PASS")), IDENTITY_ID);
        assertEquals(executor.validateOnboardingResult(context, idToken(IDENTITY_ID, "MANUAL_OK")), IDENTITY_ID);
        assertOnboardingError(context, idToken(IDENTITY_ID, "MANUAL"), "INCODE-60004", true);
        assertOnboardingError(context, idToken(IDENTITY_ID, "FAIL"), "INCODE-60003", true);
        assertOnboardingError(context, idToken(null, "PASS"), "INCODE-65009", false);
        assertOnboardingError(context, idToken(IDENTITY_ID, null), "INCODE-65009", false);

        when(associationManager.getUserForFederatedAssociation(TENANT, CONNECTION, IDENTITY_ID)).thenReturn("bob");
        assertOnboardingError(context, idToken(IDENTITY_ID, "PASS"), "INCODE-60009", true);
    }

    @Test
    public void testAccountMustBeLinkedToTheIncodeIdentity() throws Exception {

        FlowExecutionContext context = context(Collections.emptyMap());
        context.getFlowUser().addFederatedAssociation(CONNECTION, IDENTITY_ID);
        executor.validateFederatedAssociation(context, IDENTITY_ID);

        context.getFlowUser().addFederatedAssociation(CONNECTION, "interview-id");
        assertLinkRefused(() -> executor.validateFederatedAssociation(context, IDENTITY_ID));
        assertLinkRefused(() -> executor.validateFederatedAssociation(context(Collections.emptyMap()), IDENTITY_ID));
    }

    @Test
    public void testConnectionWithoutTheTemplateSettingsIsRefused() {

        // Without isExternalClaimResolutionEnabled on the step, the stock executor links sub (the interview id).
        assertLinkRefused(() -> resolveLocalClaims(context(Collections.emptyMap())));
    }

    private static void assertLinkRefused(ThrowingRunnable step) {

        try {
            step.run();
            fail("Expected INCODE-65011");
        } catch (Exception e) {
            assertTrue(e instanceof FlowEngineServerException, String.valueOf(e));
            assertEquals(((FlowEngineException) e).getErrorCode(), "INCODE-65011");
        }
    }

    private interface ThrowingRunnable {

        void run() throws Exception;
    }

    @Test
    public void testInvitedUserKeepsTheirUsername() {

        FlowExecutionContext context = context(Collections.emptyMap());
        context.setFlowType(FlowTypes.INVITED_USER_REGISTRATION.getType());
        Map<String, Object> claims = new HashMap<>();
        claims.put(USERNAME_CLAIM, IDENTITY_ID);
        executor.retainExistingUsername(context, claims);
        assertFalse(claims.containsKey(USERNAME_CLAIM));
    }

    @Test
    public void testPasswordRecoveryAsksIncodeForTheLinkedIdentity() throws Exception {

        linkUserTo(IDENTITY_ID);
        ExecutorResponse response = executor.execute(recoveryContext());

        assertEquals(response.getResult(), "EXTERNAL_REDIRECTION");
        String redirect = response.getAdditionalInfo().get(REDIRECT_URL);
        assertTrue(redirect.contains("login_hint=" + IDENTITY_ID), redirect);
        assertTrue(redirect.contains("prompt=login"), redirect);
    }

    @Test
    public void testPasswordRecoveryDoesNotRevealAMissingLink() throws Exception {

        when(associationManager.getFederatedAssociationsOfUser(any())).thenReturn(new FederatedAssociation[0]);
        ExecutorResponse response = executor.execute(recoveryContext());

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(), "INCODE-60005");
        assertEquals(response.getErrorMessage(), "{{incode.identity.verification.not.completed.message}}");
    }

    @Test
    public void testPasswordRecoveryAcceptsOnlyTheLinkedIdentity() throws Exception {

        linkUserTo(IDENTITY_ID);
        FlowExecutionContext context = recoveryContext();

        assertTrue(executor.resolveLocalClaims(context, Collections.emptyMap(), idToken(IDENTITY_ID, "PASS"))
                .isEmpty(), "Recovery leaves the profile unchanged.");
        assertTrue(context.getFlowUser().getFederatedAssociations().isEmpty(), "Recovery leaves the link unchanged.");
        assertRecoveryError(context, idToken("another-identity-id", "PASS"), "INCODE-60008");
        assertRecoveryError(context, idToken(IDENTITY_ID, "FAIL"), "INCODE-60003");
    }

    @Test
    public void testUsernameChosenEarlierInTheFlowIsKept() {

        FlowExecutionContext context = context(Collections.emptyMap());
        context.setProperty("isUsernamePatternValidationSkipped", true);
        Map<String, Object> claims = new HashMap<>();
        claims.put(USERNAME_CLAIM, IDENTITY_ID);
        executor.retainExistingUsername(context, claims);
        assertEquals(claims.get(USERNAME_CLAIM), IDENTITY_ID, "Without an earlier username Incode proposes one.");

        context.getFlowUser().addUpdatedClaim(USERNAME_CLAIM, "alice");
        executor.retainExistingUsername(context, claims);
        assertFalse(claims.containsKey(USERNAME_CLAIM));
        assertFalse(context.getProperties().containsKey("isUsernamePatternValidationSkipped"));
    }

    private void assertRecoveryError(FlowExecutionContext context, Map<String, Object> idToken, String code) {

        try {
            executor.resolveLocalClaims(context, Collections.emptyMap(), idToken);
            fail("Expected " + code);
        } catch (FlowEngineException e) {
            assertEquals(e.getErrorCode(), code);
        }
    }

    /**
     * Links the user to the given identity through an Incode connection.
     */
    private void linkUserTo(String identityId) throws Exception {

        AssociatedIdentityProvider idp = mock(AssociatedIdentityProvider.class);
        when(idp.getName()).thenReturn(CONNECTION);
        FederatedAssociation association = mock(FederatedAssociation.class);
        when(association.getIdp()).thenReturn(idp);
        when(association.getFederatedUserId()).thenReturn(identityId);
        when(associationManager.getFederatedAssociationsOfUser(any()))
                .thenReturn(new FederatedAssociation[]{association});
        FederatedAuthenticatorConfig authenticator = new FederatedAuthenticatorConfig();
        authenticator.setName("IncodeAuthenticator");
        IdentityProvider connection = new IdentityProvider();
        connection.setDefaultAuthenticatorConfig(authenticator);
        when(idpManager.getIdPByName(CONNECTION, TENANT)).thenReturn(connection);
    }

    /**
     * A password recovery flow whose earlier step resolved the user alice.
     */
    private static FlowExecutionContext recoveryContext() {

        FlowExecutionContext context = context(Collections.emptyMap());
        context.setFlowType(FlowTypes.PASSWORD_RECOVERY.getType());
        context.getFlowUser().setUsername("alice");
        context.getFlowUser().setUserStoreDomain("PRIMARY");
        context.setPortalUrl("https://localhost:9443/accounts/recovery");
        Map<String, String> properties = new HashMap<>();
        properties.put(CLIENT_ID, "face-client");
        properties.put(OAUTH2_AUTHZ_URL, "https://incode.example/oauth2/authorize");
        properties.put(SCOPES, "openid");
        context.setAuthenticatorProperties(properties);
        return context;
    }

    private void assertOnboardingError(FlowExecutionContext context, Map<String, Object> idToken, String code,
                                       boolean clientError) {

        try {
            executor.validateOnboardingResult(context, idToken);
            fail("Expected " + code);
        } catch (FlowEngineException e) {
            assertEquals(e.getErrorCode(), code);
            assertEquals(e instanceof FlowEngineClientException, clientError);
        }
    }

    /**
     * Runs the step's claim resolution, with the stock executor's dependencies mocked, for an onboarding token whose
     * sub is the interview id and whose identity_id is mapped by the connection.
     */
    private Map<String, Object> resolveLocalClaims(FlowExecutionContext context) throws Exception {

        Map<String, Object> idToken = idToken(IDENTITY_ID, "PASS");
        Map<ClaimMapping, String> remoteClaims = new HashMap<>();
        idToken.forEach((name, value) -> remoteClaims.put(ClaimMapping.build(name, name, null, false),
                String.valueOf(value)));
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setId("1");
        ExternalIdPConfig idpConfig = context.getExternalIdPConfig();
        when(idpConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(idpConfig.getUserIdClaimUri()).thenReturn("identity_id");
        when(idpConfig.getClaimMappings()).thenReturn(new ClaimMapping[]{
                ClaimMapping.build("http://wso2.org/claims/incodeIdentityId", "identity_id", null, false)});
        context.setAuthenticatorProperties(new HashMap<>());

        ClaimMetadataHandler claimMetadataHandler = mock(ClaimMetadataHandler.class);
        when(claimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(anyString(), any(), anyString(),
                anyBoolean())).thenReturn(new HashMap<>());
        FileBasedConfigurationBuilder configurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(configurationBuilder.isCustomClaimMappingsForAuthenticatorsAllowed()).thenReturn(true);
        when(configurationBuilder.isMergingCustomClaimMappingsWithDefaultClaimMappingsAllowed()).thenReturn(true);
        UserSessionStore userSessionStore = mock(UserSessionStore.class);
        when(userSessionStore.getFederatedUserId(anyString(), anyInt(), anyInt())).thenReturn("federated-user-id");

        try (MockedStatic<ClaimMetadataHandler> claimMetadataHandlerStatic = mockStatic(ClaimMetadataHandler.class);
             MockedStatic<FileBasedConfigurationBuilder> configurationBuilderStatic =
                     mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<UserSessionStore> userSessionStoreStatic = mockStatic(UserSessionStore.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtilStatic = mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtilsStatic = mockStatic(FrameworkUtils.class,
                     Mockito.CALLS_REAL_METHODS)) {
            claimMetadataHandlerStatic.when(ClaimMetadataHandler::getInstance).thenReturn(claimMetadataHandler);
            configurationBuilderStatic.when(FileBasedConfigurationBuilder::getInstance)
                    .thenReturn(configurationBuilder);
            userSessionStoreStatic.when(UserSessionStore::getInstance).thenReturn(userSessionStore);
            identityTenantUtilStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT)).thenReturn(-1234);
            frameworkUtilsStatic.when(FrameworkUtils::isJITProvisionEnhancedFeatureEnabled).thenReturn(false);
            return executor.resolveLocalClaims(context, remoteClaims, idToken);
        }
    }

    private static Map<String, Object> idToken(String identityId, String status) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "interview-id");
        claims.put("identity_id", identityId);
        claims.put("auth_overall_status", status);
        return claims;
    }

    private static Map<String, String> callback(String state) {

        Map<String, String> inputs = new HashMap<>();
        inputs.put("code", "authorization-code");
        inputs.put("state", state);
        return inputs;
    }

    private static FlowExecutionContext callbackContext() {

        FlowExecutionContext context = context(callback("state-sent"));
        context.setProperty("state", "state-sent");
        return context;
    }

    private static FlowExecutionContext context(Map<String, String> userInputs) {

        ExternalIdPConfig idpConfig = mock(ExternalIdPConfig.class);
        when(idpConfig.getIdPName()).thenReturn(CONNECTION);
        FlowExecutionContext context = new FlowExecutionContext();
        context.setTenantDomain(TENANT);
        context.setExternalIdPConfig(idpConfig);
        context.setFlowUser(new FlowUser());
        context.setUserInputData(new HashMap<>(userInputs));
        return context;
    }
}
