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

package org.wso2.carbon.identity.verification.incode.connector.constants;

/**
 * Error catalogue of the connector.
 */
public final class ErrorConstants {

    public static final String INCODE_ERROR_PREFIX = "INCODE-";

    private ErrorConstants() {
    }

    /**
     * {@code message} is the user-facing text and {@code description} the diagnostic detail, which is only logged.
     * A user-facing error also has an i18n key: the portals render {@code <key>.message} and
     * {@code <key>.description} from their resource bundles.
     */
    public enum ErrorMessage {

        // Client errors - INCODE-60xxx.
        IDENTITY_NOT_LINKED("60001",
                "Your account is not linked to a verified identity. Please contact your administrator.",
                "No Incode connection has linked an identity to the user.",
                "incode.identity.verification.not.linked"),
        // Incode returns access_denied both when the user cancels and when it does not verify the user.
        VERIFICATION_CANCELLED("60002",
                "Identity verification was cancelled or not completed. Please try again.",
                "Incode returned access_denied on the callback: the user cancelled, or Incode did not verify the "
                        + "user, for example because the face did not match.",
                "incode.identity.verification.not.completed"),
        VERIFICATION_FAILED("60003",
                "Your identity could not be verified.",
                "Incode reported a status that is not accepted.",
                "incode.identity.verification.failed"),
        VERIFICATION_PENDING_REVIEW("60004",
                "Your identity verification needs a manual review. Please try again later.",
                "Incode reported a status that needs a manual review.",
                "incode.identity.verification.pending.review"),
        VERIFICATION_NOT_COMPLETED("60005",
                "Identity verification could not be completed. Please try again.",
                "Incode returned an error other than access_denied, or the account cannot be verified.",
                "incode.identity.verification.not.completed"),
        INVALID_STATE("60007",
                "The verification response is invalid or has expired. Please start again.",
                "The callback state does not match the state sent in the authorization request.",
                "incode.identity.verification.session.expired"),
        LOGIN_IDENTITY_MISMATCH("60008",
                "The verified identity does not match the account you are signing in to.",
                "The identity_id returned by Incode does not match the identity linked to the user.",
                "incode.identity.verification.login.identity.mismatch"),
        IDENTITY_ALREADY_LINKED("60009",
                "This identity is already registered. Sign in with your existing account.",
                "The identity_id returned by Incode is already linked to a user on the connection.",
                "incode.identity.verification.already.linked"),
        NO_LOCAL_USER("60010",
                "Sign in with your account before verifying your identity.",
                "The Incode login step needs a local user authenticated by the subject identifier step.",
                "incode.identity.verification.no.local.user"),

        // Server errors - INCODE-65xxx.
        INVALID_CONFIGURATION("65001",
                "The Incode connection is not configured correctly.",
                "The Incode login step must follow the subject identifier step of the login flow."),
        VERIFICATION_REQUEST_FAILED("65004",
                "Could not complete the identity verification.",
                "The OpenID Connect exchange with Incode failed.",
                "incode.identity.verification.not.completed"),
        SIGNUP_UNAVAILABLE("65009",
                "Identity verification is not available for sign-up. Please contact your administrator.",
                "The Incode token has no identity_id or auth_overall_status claim. Registration needs an onboarding "
                        + "client whose Workflow creates the identity.",
                "incode.identity.verification.signup.unavailable"),
        RESOLVING_ASSOCIATION("65010",
                "Could not read the identity linked to the account.",
                "Error resolving the Incode identity association."),
        IDENTITY_NOT_LINKED_BY_CONNECTION("65011",
                "The Incode connection is not configured correctly.",
                "The connection did not link the account to the Incode identity_id. Save the flow again so that "
                        + "the Incode step gets isExternalClaimResolutionEnabled, create the connection from the "
                        + "Incode Identity Verification template, and map the OpenID Connect claim identity_id to "
                        + "http://wso2.org/claims/incodeIdentityId.");

        private final String code;
        private final String message;
        private final String description;
        private final String i18nKey;

        ErrorMessage(String code, String message, String description) {

            this(code, message, description, null);
        }

        ErrorMessage(String code, String message, String description, String i18nKey) {

            this.code = code;
            this.message = message;
            this.description = description;
            this.i18nKey = i18nKey;
        }

        /**
         * @return the prefixed error code, e.g. {@code INCODE-60009}.
         */
        public String getCode() {

            return INCODE_ERROR_PREFIX + code;
        }

        public String getMessage() {

            return message;
        }

        public String getDescription() {

            return description;
        }

        public String getI18nKey() {

            return i18nKey;
        }

        public boolean isClientError() {

            return code.startsWith("60");
        }

        /**
         * The heading a portal renders. The {@code {{ }}} wrapping marks it as an i18n token.
         *
         * @return e.g. {@code {{incode.identity.verification.already.linked.message}}}, or the plain message.
         */
        public String getUserMessageToken() {

            return i18nKey == null ? message : "{{" + i18nKey + ".message}}";
        }

        /**
         * The body a portal renders, wrapped as with {@link #getUserMessageToken()}.
         *
         * @return e.g. {@code {{incode.identity.verification.already.linked.description}}}, or the plain message.
         */
        public String getUserDescriptionToken() {

            return i18nKey == null ? message : "{{" + i18nKey + ".description}}";
        }

        @Override
        public String toString() {

            return getCode() + " - " + description;
        }
    }
}
