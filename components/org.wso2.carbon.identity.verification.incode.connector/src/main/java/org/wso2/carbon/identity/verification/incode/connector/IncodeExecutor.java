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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.metadata.FlowExecutorMetadata;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerException;
import org.wso2.carbon.identity.verification.incode.connector.constants.Constants;
import org.wso2.carbon.identity.verification.incode.connector.constants.ErrorConstants;
import org.wso2.carbon.identity.verification.incode.connector.constants.ErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.incode.connector.util.IncodeUtils;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_ERROR;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;

/**
 * Incode step for self-registration, invited-user registration and password recovery. The OpenID Connect executor
 * does the exchange and maps the claims. In registration this class checks the Incode result, refuses an identity
 * that is already registered, checks the link to the Incode identity and keeps the account's username; in password
 * recovery it re-verifies the identity linked to the user. Errors carry Incode codes.
 */
public class IncodeExecutor extends OpenIDConnectExecutor {

    private static final Log LOG = LogFactory.getLog(IncodeExecutor.class);

    @Override
    public String getName() {

        return Constants.EXECUTOR_NAME;
    }

    @Override
    public String getAMRValue() {

        return Constants.AUTHENTICATOR_NAME;
    }

    @Override
    public Set<FlowTypes> getSupportedFlowTypes() {

        return EnumSet.of(FlowTypes.REGISTRATION, FlowTypes.INVITED_USER_REGISTRATION, FlowTypes.PASSWORD_RECOVERY);
    }

    @Override
    public FlowExecutorMetadata getExecutorMetadata() {

        return FlowExecutorMetadata.builder()
                .displayName(Constants.ExecutorMetadata.DISPLAY_NAME)
                .description(Constants.ExecutorMetadata.DESCRIPTION)
                .icon(Constants.ExecutorMetadata.ICON)
                .associatedAuthenticator(Constants.AUTHENTICATOR_NAME)
                .connectionRequired(true)
                .externalClaimResolutionEnabled(true)
                .build();
    }

    /**
     * Handles the Incode callback here, so that an Incode error ends the step instead of starting a new redirect and
     * error codes reach the portal. The first call, which has neither a code nor a state and redirects to Incode, is
     * the stock executor's; a callback must carry both.
     */
    @Override
    public ExecutorResponse execute(FlowExecutionContext context) {

        Map<String, String> inputs = context.getUserInputData() == null ? Collections.emptyMap() :
                context.getUserInputData();
        String oauthError = inputs.get(OAUTH2_ERROR);
        if (StringUtils.isNotBlank(oauthError)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Incode returned an error on the " + context.getFlowType() + " callback. error="
                        + oauthError + ", error_description=" + inputs.get(Constants.ERROR_DESCRIPTION));
            }
            return buildErrorResponse(Constants.ACCESS_DENIED.equals(oauthError) ?
                    ErrorMessage.VERIFICATION_CANCELLED : ErrorMessage.VERIFICATION_NOT_COMPLETED);
        }
        String code = inputs.get(OAUTH2_GRANT_TYPE_CODE);
        String state = inputs.get(OAUTH2_PARAM_STATE);
        if (code == null && state == null) {
            ExecutorResponse error = isPasswordRecovery(context) ? addLinkedIdentityAsLoginHint(context) : null;
            return error != null ? error : super.execute(context);
        }
        Object expectedState = context.getProperty(OAUTH2_PARAM_STATE);
        if (StringUtils.isBlank(state) || expectedState == null || !state.equals(expectedState.toString())) {
            return buildErrorResponse(ErrorMessage.INVALID_STATE);
        }
        if (StringUtils.isBlank(code)) {
            return buildErrorResponse(ErrorMessage.VERIFICATION_NOT_COMPLETED);
        }
        try {
            ExecutorResponse response = new ExecutorResponse(STATUS_COMPLETE);
            response.setUpdatedUserClaims(resolveUserAttributes(context, code));
            return response;
        } catch (FlowEngineException e) {
            if (StringUtils.startsWith(e.getErrorCode(), ErrorConstants.INCODE_ERROR_PREFIX)) {
                return buildErrorResponse(e instanceof FlowEngineClientException ? STATUS_USER_ERROR : STATUS_ERROR,
                        e.getErrorCode(), e.getMessage(), e.getDescription());
            }
            LOG.error("Error completing the Incode sign-up step.", e);
            return buildErrorResponse(ErrorMessage.VERIFICATION_REQUEST_FAILED);
        }
    }

    @Override
    protected Map<String, Object> resolveLocalClaims(FlowExecutionContext context,
                                                     Map<ClaimMapping, String> remoteClaimMappings,
                                                     Map<String, Object> idTokenClaims) throws FlowEngineException {

        if (isPasswordRecovery(context)) {
            validateFaceAuthenticationResult(context, idTokenClaims);
            // The step only gates the password reset: the profile and the link stay as they are.
            return new HashMap<>();
        }
        String identityId = validateOnboardingResult(context, idTokenClaims);
        Map<String, Object> localClaims = super.resolveLocalClaims(context, remoteClaimMappings, idTokenClaims);
        validateFederatedAssociation(context, identityId);
        retainExistingUsername(context, localClaims);
        return localClaims;
    }

    /**
     * The connection links the account to its subject attribute, identity_id, which is the only stable identifier
     * Incode returns (sub is the per-session interview id). Login trusts that link, so a connection that links anything
     * else is refused.
     */
    void validateFederatedAssociation(FlowExecutionContext context, String identityId) throws FlowEngineException {

        if (!identityId.equals(context.getFlowUser().getFederatedAssociations()
                .get(context.getExternalIdPConfig().getIdPName()))) {
            throw handleFlowEngineException(ErrorMessage.IDENTITY_NOT_LINKED_BY_CONNECTION);
        }
    }

    /**
     * Checks the Incode result and refuses an identity that is already registered through any Incode connection of
     * the organization, the connections whose links login accepts. User provisioning would otherwise create the user
     * before failing on the link.
     *
     * @return the Incode identity.
     */
    String validateOnboardingResult(FlowExecutionContext context, Map<String, Object> idTokenClaims)
            throws FlowEngineException {

        String identityId = getClaim(idTokenClaims, Constants.IDENTITY_ID_CLAIM);
        String status = getClaim(idTokenClaims, Constants.STATUS_CLAIM);
        if (identityId == null || status == null) {
            throw handleFlowEngineException(ErrorMessage.SIGNUP_UNAVAILABLE);
        }
        if (!Constants.ACCEPTED_ONBOARDING_STATUSES.contains(status)) {
            throw handleFlowEngineException(Constants.PENDING_REVIEW_STATUSES.contains(status) ?
                    ErrorMessage.VERIFICATION_PENDING_REVIEW : ErrorMessage.VERIFICATION_FAILED);
        }
        boolean linked;
        try {
            linked = IncodeUtils.isIdentityLinked(identityId, context.getExternalIdPConfig().getIdPName(),
                    context.getTenantDomain());
        } catch (FederatedAssociationManagerException | IdentityProviderManagementException e) {
            LOG.error("Error checking whether the Incode identity is already registered.", e);
            throw handleFlowEngineException(ErrorMessage.RESOLVING_ASSOCIATION);
        }
        if (linked) {
            throw handleFlowEngineException(ErrorMessage.IDENTITY_ALREADY_LINKED);
        }
        return identityId;
    }

    /**
     * Password recovery re-verifies the account owner: sends the Incode identity linked to the user as login_hint
     * with prompt=login. An account without a link, including a username that does not exist, gets the generic
     * not-completed error before Incode is called.
     *
     * @return the error that stops the step, or null.
     */
    ExecutorResponse addLinkedIdentityAsLoginHint(FlowExecutionContext context) {

        if (StringUtils.isBlank(context.getFlowUser().getUsername())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Password recovery cannot verify the user: no user is identified yet. Place the Incode "
                        + "step after the step that identifies the user.");
            }
            return buildErrorResponse(ErrorMessage.VERIFICATION_NOT_COMPLETED);
        }
        String identityId;
        try {
            identityId = getLinkedIdentity(context);
        } catch (FederatedAssociationManagerException | IdentityProviderManagementException e) {
            LOG.error("Error reading the Incode identity linked to the user.", e);
            return buildErrorResponse(ErrorMessage.RESOLVING_ASSOCIATION);
        }
        if (identityId == null) {
            LOG.info("Password recovery cannot verify the user: the account does not exist or is not linked to an "
                    + "Incode identity.");
            return buildErrorResponse(ErrorMessage.VERIFICATION_NOT_COMPLETED);
        }
        context.getAuthenticatorProperties().put(Constants.EXPECTED_IDENTITY, identityId);
        return null;
    }

    @Override
    protected Map<String, String> getAdditionalQueryParams(Map<String, String> authenticatorProperties) {

        Map<String, String> params = super.getAdditionalQueryParams(authenticatorProperties);
        String identityId = authenticatorProperties.get(Constants.EXPECTED_IDENTITY);
        if (identityId != null) {
            params.put(Constants.PROMPT, Constants.PROMPT_LOGIN);
            params.put(Constants.LOGIN_HINT, identityId);
        }
        return params;
    }

    /**
     * In password recovery Incode must return the identity linked to the user and a passing status.
     */
    void validateFaceAuthenticationResult(FlowExecutionContext context, Map<String, Object> idTokenClaims)
            throws FlowEngineException {

        String identityId;
        try {
            identityId = getLinkedIdentity(context);
        } catch (FederatedAssociationManagerException | IdentityProviderManagementException e) {
            LOG.error("Error reading the Incode identity linked to the user.", e);
            throw handleFlowEngineException(ErrorMessage.RESOLVING_ASSOCIATION);
        }
        if (identityId == null || !identityId.equals(getClaim(idTokenClaims, Constants.IDENTITY_ID_CLAIM))) {
            throw handleFlowEngineException(ErrorMessage.LOGIN_IDENTITY_MISMATCH);
        }
        String status = getClaim(idTokenClaims, Constants.STATUS_CLAIM);
        if (status == null || !Constants.ACCEPTED_FACE_STATUSES.contains(status)) {
            throw handleFlowEngineException(ErrorMessage.VERIFICATION_FAILED);
        }
    }

    /**
     * The Incode identity linked to the user of the flow, or null when the flow has no user or the user no link.
     */
    private static String getLinkedIdentity(FlowExecutionContext context)
            throws FederatedAssociationManagerException, IdentityProviderManagementException {

        String username = context.getFlowUser().getUsername();
        if (StringUtils.isBlank(username)) {
            return null;
        }
        String userStoreDomain = context.getFlowUser().getUserStoreDomain();
        User user = new User();
        user.setTenantDomain(context.getTenantDomain());
        user.setUserStoreDomain(StringUtils.isNotBlank(userStoreDomain) ? userStoreDomain :
                UserCoreUtil.extractDomainFromName(username));
        user.setUserName(UserCoreUtil.removeDomainFromName(username));
        return IncodeUtils.getLinkedIdentity(user);
    }

    private static boolean isPasswordRecovery(FlowExecutionContext context) {

        return FlowTypes.PASSWORD_RECOVERY.getType().equals(context.getFlowType());
    }

    /**
     * The username chosen earlier in the flow, or the invited user's own, belongs to the account, so the step keeps
     * it in any order.
     */
    void retainExistingUsername(FlowExecutionContext context, Map<String, Object> localClaims) {

        if (FlowTypes.INVITED_USER_REGISTRATION.getType().equals(context.getFlowType())
                || StringUtils.isNotBlank(context.getFlowUser().getClaims().get(USERNAME_CLAIM_URI))) {
            localClaims.remove(USERNAME_CLAIM_URI);
            context.getProperties().remove(Constants.USERNAME_PATTERN_VALIDATION_SKIPPED);
            UserCoreUtil.removeSkipUsernamePatternValidationThreadLocal();
        }
    }

    private static String getClaim(Map<String, Object> claims, String claimName) {

        Object value = claims.get(claimName);
        return value == null || StringUtils.isBlank(value.toString()) ? null : value.toString();
    }

    private static FlowEngineException handleFlowEngineException(ErrorMessage error) {

        IncodeUtils.log(LOG, error);
        return error.isClientError() ?
                new FlowEngineClientException(error.getCode(), error.getUserMessageToken(),
                        error.getUserDescriptionToken()) :
                new FlowEngineServerException(error.getCode(), error.getUserMessageToken(),
                        error.getUserDescriptionToken());
    }

    private static ExecutorResponse buildErrorResponse(ErrorMessage error) {

        IncodeUtils.log(LOG, error);
        return buildErrorResponse(error.isClientError() ? STATUS_USER_ERROR : STATUS_ERROR, error.getCode(),
                error.getUserMessageToken(), error.getUserDescriptionToken());
    }

    private static ExecutorResponse buildErrorResponse(String result, String code, String message, String description) {

        ExecutorResponse response = new ExecutorResponse();
        response.setResult(result);
        response.setErrorCode(code);
        response.setErrorMessage(message);
        response.setErrorDescription(description);
        return response;
    }
}
