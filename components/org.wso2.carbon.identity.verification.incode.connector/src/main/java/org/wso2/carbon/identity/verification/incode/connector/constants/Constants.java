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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Constants of the Incode connector.
 */
public final class Constants {

    public static final String AUTHENTICATOR_NAME = "IncodeAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Incode";
    public static final String EXECUTOR_NAME = "IncodeExecutor";

    public static final String IDENTITY_ID_CLAIM = "identity_id";
    public static final String STATUS_CLAIM = "auth_overall_status";

    public static final List<String> ACCEPTED_ONBOARDING_STATUSES =
            Collections.unmodifiableList(Arrays.asList("PASS", "OK", "MANUAL_OK"));
    public static final List<String> PENDING_REVIEW_STATUSES =
            Collections.unmodifiableList(Arrays.asList("MANUAL", "MANUAL_PENDING", "WARN"));
    public static final List<String> ACCEPTED_FACE_STATUSES =
            Collections.unmodifiableList(Arrays.asList("PASS", "OK"));

    public static final String ACCESS_DENIED = "access_denied";
    public static final String ERROR_DESCRIPTION = "error_description";
    public static final String LOGIN_HINT = "login_hint";
    public static final String PROMPT = "prompt";
    public static final String PROMPT_LOGIN = "login";
    public static final String EXPECTED_IDENTITY = "incodeExpectedIdentity";
    public static final String RETRY_PAGE_STATUS_KEY = "unable.to.proceed";
    // OpenIDConnectExecutor keeps this property name private; IncodeExecutorTest fails if the two differ.
    public static final String USERNAME_PATTERN_VALIDATION_SKIPPED = "isUsernamePatternValidationSkipped";

    private Constants() {
    }

    /**
     * How the sign-up step appears in the flow builder.
     */
    public static final class ExecutorMetadata {

        public static final String DISPLAY_NAME = "Incode Verification";
        public static final String DESCRIPTION = "Verify user identity with Incode.";
        public static final String ICON = "assets/images/icons/incode.svg";

        private ExecutorMetadata() {
        }
    }
}
