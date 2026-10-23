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
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerException;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.FederatedAssociation;
import org.wso2.carbon.identity.verification.incode.connector.constants.Constants;
import org.wso2.carbon.identity.verification.incode.connector.constants.ErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.incode.connector.internal.IncodeConnectorDataHolder;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_ERROR;

/**
 * Incode face check in a login flow, after the step that identifies the user. Sends the identity linked to that user
 * as login_hint and requires Incode to return the same identity. Everything else is the stock OIDC authenticator.
 */
public class IncodeAuthenticator extends OpenIDConnectAuthenticator {

    private static final long serialVersionUID = 1L;
    private static final Log LOG = LogFactory.getLog(IncodeAuthenticator.class);

    @Override
    public String getName() {

        return Constants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return Constants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return false;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        ErrorMessage error = addLinkedIdentityAsLoginHint(context);
        if (error != null) {
            sendToRetryPage(request, response, context, error);
            return;
        }
        super.initiateAuthenticationRequest(request, response, context);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        Object expectedIdentity = context.getProperty(Constants.EXPECTED_IDENTITY);
        context.removeProperty(Constants.EXPECTED_IDENTITY);
        String oauthError = request.getParameter(OAUTH2_ERROR);
        if (StringUtils.isNotBlank(oauthError)) {
            throw handleAuthenticationFailedException(context, Constants.ACCESS_DENIED.equals(oauthError) ?
                    ErrorMessage.VERIFICATION_CANCELLED : ErrorMessage.VERIFICATION_NOT_COMPLETED);
        }
        super.processAuthenticationResponse(request, response, context);
        ErrorMessage error = validateFaceAuthenticationResult(context.getSubject().getUserAttributes(),
                expectedIdentity);
        if (error != null) {
            throw handleAuthenticationFailedException(context, error);
        }
    }

    /**
     * Incode must return the identity sent as login_hint, and a passing status when it sends one.
     *
     * @return the error that fails the step, or null.
     */
    static ErrorMessage validateFaceAuthenticationResult(Map<ClaimMapping, String> claims, Object expectedIdentity) {

        if (expectedIdentity == null
                || !expectedIdentity.equals(getRemoteClaim(claims, Constants.IDENTITY_ID_CLAIM))) {
            return ErrorMessage.LOGIN_IDENTITY_MISMATCH;
        }
        String status = getRemoteClaim(claims, Constants.STATUS_CLAIM);
        return status == null || Constants.ACCEPTED_FACE_STATUSES.contains(status) ? null :
                ErrorMessage.VERIFICATION_FAILED;
    }

    /**
     * Finds the user of the subject identifier step, which must be an earlier step, and adds the Incode identity
     * linked to that user as login_hint.
     *
     * @return the error that stops the request, or null.
     */
    ErrorMessage addLinkedIdentityAsLoginHint(AuthenticationContext context) {

        Map<Integer, StepConfig> steps = context.getSequenceConfig().getStepMap();
        StepConfig subjectStep = steps.values().stream().filter(StepConfig::isSubjectIdentifierStep).findFirst()
                .orElse(null);
        if (subjectStep == null || subjectStep == steps.get(context.getCurrentStep())) {
            return ErrorMessage.INVALID_CONFIGURATION;
        }
        AuthenticatedUser user = subjectStep.getAuthenticatedUser();
        if (user == null || user.isFederatedUser()) {
            return ErrorMessage.NO_LOCAL_USER;
        }
        String identityId;
        try {
            identityId = getLinkedIdentity(user);
        } catch (FederatedAssociationManagerException | IdentityProviderManagementException e) {
            LOG.error("Error reading the Incode identity linked to the user.", e);
            return ErrorMessage.RESOLVING_ASSOCIATION;
        }
        if (identityId == null) {
            return ErrorMessage.IDENTITY_NOT_LINKED;
        }
        Map<String, String> properties = context.getAuthenticatorProperties();
        properties.put(FrameworkConstants.QUERY_PARAMS, getQueryStringWithLoginHint(
                properties.get(FrameworkConstants.QUERY_PARAMS), identityId));
        context.setProperty(Constants.EXPECTED_IDENTITY, identityId);
        return null;
    }

    /**
     * Makes Incode run a new face check for the linked identity: sets prompt=login and login_hint, replacing any
     * values the connection's query parameters carry.
     */
    static String getQueryStringWithLoginHint(String queryParams, String identityId) {

        List<String> params = new ArrayList<>();
        if (StringUtils.isNotBlank(queryParams)) {
            for (String param : queryParams.split("&")) {
                String name = param.split("=", 2)[0];
                if (StringUtils.isNotBlank(param) && !Constants.PROMPT.equals(name)
                        && !Constants.LOGIN_HINT.equals(name)) {
                    params.add(param);
                }
            }
        }
        params.add(Constants.PROMPT + "=" + Constants.PROMPT_LOGIN);
        params.add(Constants.LOGIN_HINT + "=" + URLEncoder.encode(identityId, StandardCharsets.UTF_8));
        return String.join("&", params);
    }

    /**
     * The user's link to an identity made by an Incode connection. Sign-up links the user through the onboarding
     * connection, so the link is found by the connection's authenticator, not by this connection's name.
     */
    static String getLinkedIdentity(User user)
            throws FederatedAssociationManagerException, IdentityProviderManagementException {

        for (FederatedAssociation association :
                IncodeConnectorDataHolder.getFederatedAssociationManager().getFederatedAssociationsOfUser(user)) {
            IdentityProvider idp = IncodeConnectorDataHolder.getIdpManager()
                    .getIdPByName(association.getIdp().getName(), user.getTenantDomain());
            FederatedAuthenticatorConfig authenticator = idp == null ? null : idp.getDefaultAuthenticatorConfig();
            if (authenticator != null && Constants.AUTHENTICATOR_NAME.equals(authenticator.getName())) {
                return association.getFederatedUserId();
            }
        }
        return null;
    }

    private static String getRemoteClaim(Map<ClaimMapping, String> claims, String claimName) {

        return claims.entrySet().stream()
                .filter(claim -> claimName.equals(claim.getKey().getRemoteClaim().getClaimUri()))
                .map(Map.Entry::getValue).findFirst().orElse(null);
    }

    private void sendToRetryPage(HttpServletRequest request, HttpServletResponse response,
                                 AuthenticationContext context, ErrorMessage error)
            throws AuthenticationFailedException {

        setErrorInformation(context, error);
        try {
            FrameworkUtils.sendToRetryPage(request, response, context,
                    error.getI18nKey() == null ? Constants.RETRY_PAGE_STATUS_KEY :
                            error.getUserMessageToken(), error.getUserDescriptionToken());
            context.setCurrentAuthenticator(getName());
        } catch (IOException e) {
            throw new AuthenticationFailedException(error.getCode(), error.getMessage(), e);
        }
    }

    private AuthenticationFailedException handleAuthenticationFailedException(AuthenticationContext context,
                                                                              ErrorMessage error) {

        setErrorInformation(context, error);
        return new AuthenticationFailedException(error.getCode(), error.getMessage());
    }

    private static void setErrorInformation(AuthenticationContext context, ErrorMessage error) {

        if (error.isClientError()) {
            LOG.info(error);
        } else {
            LOG.error(error);
        }
        context.setProperty(FrameworkConstants.AUTH_ERROR_CODE, error.getCode());
        context.setProperty(FrameworkConstants.AUTH_ERROR_MSG, error.getMessage());
    }
}
