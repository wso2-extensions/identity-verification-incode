# WSO2 Identity Server — Incode Identity Verification Connector

This connector adds [Incode](https://incode.com) identity verification to WSO2 Identity Server as a federated OpenID
Connect connection. It extends the OpenID Connect authenticator and sign-up executor that ship with WSO2 Identity
Server and adds only the Incode-specific checks.

- **Self-registration**: an Incode step verifies the user (ID document and selfie). The account is created only for an
  accepted result, and it is linked to the verified Incode identity.
- **Invited-user registration**: the invited user verifies with Incode before setting a password, and the account is
  linked to the verified Incode identity.
- **Login**: an Incode step after the step that identifies the user runs Incode face authentication for the identity
  linked to that user, and accepts only the same identity.
- **Password recovery**: an Incode step after the step that identifies the user re-verifies the linked identity with
  face authentication before the password can be reset.

| Component | Name | Used in |
|---|---|---|
| Executor | `IncodeExecutor` (the **Incode** step in the flow builder) | Self-registration, invited-user registration and password recovery flows |
| Authenticator | `IncodeAuthenticator` (also the `amr` value) | Application login flows |
| Connection template | `incode-idv` (**Incode Identity Verification**) | Connections |

---

## How it works

Incode returns two identifiers in its ID token: `sub`, which changes with every verification session, and
`identity_id`, which identifies the person. The connector links the WSO2 account to `identity_id` as a federated
association and trusts only that link.

1. **Sign-up**: the Incode step checks the verification result and refuses an identity that is already registered.
   The OpenID Connect sign-up step then maps the Incode claims to the user's attributes and links the account to
   `identity_id`, the connection's subject attribute, the same way federated login resolves it. The Incode step
   refuses the sign-up if the account is linked to anything else.
   Invited-user registration works the same way for the invited account, and keeps its username.
2. **Login and password recovery**: the Incode step reads the link of the user identified by the earlier step, sends
   it to Incode as `login_hint` with `prompt=login`, and accepts the step only if Incode returns the same
   `identity_id`. Password recovery changes neither the profile nor the link.

Users cannot create or change links. The profile attributes the connection fills in are for display only.

---

## Prerequisites

- WSO2 Identity Server 7.x.
- Platform versions with external claim resolution: the framework lets an executor declare it, the flow management
  API sets `isExternalClaimResolutionEnabled` on the executor's steps when a flow is saved, and the OpenID Connect
  sign-up step then honors the connection's external claim mappings
  ([identity-outbound-auth-oidc#243](https://github.com/wso2-extensions/identity-outbound-auth-oidc/pull/243)).
  Without them, sign-up is refused with `INCODE-65011`.
- JDK 21 and Maven 3.6 or later.
- An Incode environment where you can create OpenID Connect clients.

---

## Building

```bash
mvn clean install
```

| Artifact | Location |
|---|---|
| Connector bundle (authenticator and executor) | `components/org.wso2.carbon.identity.verification.incode.connector/target/org.wso2.carbon.identity.verification.incode.connector-<version>.jar` |
| Release archive (bundle, connection template and logo) | `components/org.wso2.carbon.identity.verification.incode.connector/target/wso2is-incode-connector-<version>.zip` |

---

## Deployment

Extract the release archive and copy its contents into `<IS_HOME>`, then restart the server (connection templates
are read at startup):

| Artifact in the archive | Destination, under `<IS_HOME>` |
|---|---|
| `dropins/` (connector bundle) | `repository/components/dropins/` |
| `connections/incode-idv/` (connection template) | `repository/resources/identity/extensions/connections/` |
| `images/logos/incode.svg` (logo) | `console/resources/connections/assets/images/logos/`, `myaccount/resources/connections/assets/images/logos/` and `authenticationendpoint/libs/themes/default/assets/images/identity-providers/`, under `repository/deployment/server/webapps/` |
| `images/icons/incode.svg` (square icon of the **Incode** step in the flow builder) | `console/resources/assets/images/icons/`, under `repository/deployment/server/webapps/` |

---

## Incode setup

Create two confidential OpenID Connect clients in Incode:

| Client | Purpose | Redirect URI |
|---|---|---|
| Onboarding | Verifies the user at sign-up and invited-user registration. Its onboarding must create an identity, so that the ID token carries `identity_id` and `auth_overall_status`. | `https://<host>/accounts/register` |
| Face authentication | Verifies the user at login and password recovery, with the user's `identity_id` as `login_hint`. | `https://<host>/commonauth` and `https://<host>/accounts/recovery` |

For a tenant, add `/t/<tenant>` after the host. These are the default portal URLs: self-registration and
invited-user registration redirect to `/accounts/register`, and password recovery to `/accounts/recovery`. If custom
portal URLs are configured in branding (**Self Signup** and **Recovery Portal**), self-registration redirects to the
Self Signup URL, and invited-user registration and password recovery to the Recovery Portal URL. In that case register
the Self Signup and Recovery Portal URLs on the onboarding client, and the Recovery Portal URL on the face
authentication client. See Incode's developer documentation for creating OpenID Connect clients.

---

## WSO2 Identity Server setup

1. **Attributes** (Console > User Attributes & Stores > Attributes):
   - Create the local attributes `http://wso2.org/claims/incodeIdentityId`, `http://wso2.org/claims/incodeInterviewId`
     and `http://wso2.org/claims/incodeOnboardingStatus`.
   - Under **OpenID Connect**, add the attribute `identity_id` mapped to `http://wso2.org/claims/incodeIdentityId`.
     Federated login and sign-up resolve the connection's subject attribute through it.
2. **Connections** (Console > Connections > New Connection > **Incode Identity Verification**): create one connection
   per Incode client, for example "Incode Onboarding" and "Incode Face". The template maps `identity_id`,
   `interview_id` and `auth_overall_status` to the local attributes, sets `identity_id` as the subject attribute, and
   sets the connection property `IsUserIdInClaims` to `true` (the console does not show it). Keep Just-in-Time
   provisioning off.
3. **Self-registration** (Console > Flows > Self Registration): add the **Incode** step with the onboarding
   connection. It can come before or after the form that asks for the username and password; a username chosen in
   the form is kept.
4. **Invited-user registration** (Console > Flows): add the **Incode** step with the onboarding connection before the
   step that sets the password.
5. **External claim resolution**: when a flow with the Incode step is saved, the step gets
   `isExternalClaimResolutionEnabled` set to `true` in its metadata, next to `idpName`. The connector declares it, so
   nothing needs to be configured. With it, the OpenID Connect sign-up step honors the connection's external claim
   mappings (the Incode attributes) and links the account to `identity_id`. Steps of other executors do not get it.
6. **Password recovery** (Console > Flows): add the **Incode** step with the face authentication connection after the
   step that identifies the user.
7. **Login** (the application's login flow): keep **Username & Password**, or another local first factor, as step 1
   and as the subject identifier step, and add the face authentication connection as a later step. No adaptive script
   is needed.

---

## Runtime behaviour

**Sign-up**

| Incode result | Outcome |
|---|---|
| Status `PASS`, `OK` or `MANUAL_OK`, and a new `identity_id` | Account created and linked to `identity_id` |
| Status `MANUAL`, `MANUAL_PENDING` or `WARN` | Refused, pending review (`INCODE-60004`) |
| Any other status | Refused (`INCODE-60003`) |
| `identity_id` already linked on the connection | Refused before the account is created (`INCODE-60009`) |
| User cancelled at Incode | Refused (`INCODE-60002`) |

**Invited-user registration**: the same results as sign-up; on success the invited account is linked to
`identity_id` and gets the Incode attributes.

**Password recovery**

| Situation | Outcome |
|---|---|
| Returned `identity_id` matches the link, status `PASS` or `OK` (when present) | Step succeeds; the password can be reset |
| The account has no Incode link | Refused with the generic `INCODE-60005`, before Incode is called |
| Another identity returned, or a failing status | Refused (`INCODE-60008`, `60003`) |
| User cancelled at Incode | Refused (`INCODE-60002`) |

**Login**

| Situation | Outcome |
|---|---|
| Returned `identity_id` matches the link, status `PASS` or `OK` (when present) | Step succeeds |
| No link, no local user from the subject step, or the Incode step is the subject step | WSO2 error page (`INCODE-60001`, `60010`, `65001`) |
| Cancelled, another identity returned, or a failing status | The application receives `INCODE-60002`, `60008` or `60003` with a user-friendly description, or the application's adaptive script handles the failure in `onFail` |

---

## Error codes

Client errors are `INCODE-60xxx`, server and configuration errors `INCODE-65xxx`. Portals translate the keys
`incode.identity.verification.<key>.message` and `.description`; errors without a key show a generic message.

| Code | Meaning | i18n key |
|---|---|---|
| 60001 | The account is not linked to an Incode identity | `not.linked` |
| 60002 | Verification cancelled | `cancelled` |
| 60003 | Verification failed | `failed` |
| 60004 | Verification needs a manual review | `pending.review` |
| 60005 | The verification could not be completed: Incode returned another error, or (password recovery) the account has no Incode link | `not.completed` |
| 60007 | The verification response is invalid or expired | `session.expired` |
| 60008 | The verified identity does not match the account | `login.identity.mismatch` |
| 60009 | The identity is already registered | `already.linked` |
| 60010 | No local user from an earlier step | `no.local.user` |
| 65001 | The Incode login step must follow the subject identifier step | — |
| 65004 | The OpenID Connect exchange with Incode failed | `not.completed` |
| 65009 | The Incode token has no identity or status | `signup.unavailable` |
| 65010 | The linked identity could not be read | — |
| 65011 | The connection did not link the account to `identity_id` | — |

---

## Security notes

- Do not use `incodeIdentityId`, `incodeOnboardingStatus` or `incodeInterviewId` for authorization decisions: they are
  profile attributes, which users can update through self-service APIs. The connector uses the link.
- Keep Just-in-Time provisioning off on Incode connections.
- Use `https` endpoints for the Incode connections.
- Do not enable ID token logging in production: Incode tokens carry identity data.

---

## Limitations

- App-native (API-based) authentication is not supported by the login step.
- The duplicate check covers the onboarding connection that runs the step; use one onboarding connection per
  organization.
- In password recovery, an account without an Incode link is refused before Incode is called, while a linked account
  is redirected to Incode, so a user who passes the earlier step can tell whether the account is linked.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| The Incode step is missing in the flow builder | The bundle is not active: check `wso2carbon.log` for `IncodeConnectorServiceComponent` |
| Sign-up fails with `INCODE-65011` | The flow was saved before the connector was deployed (save it again), the OpenID Connect attribute `identity_id` is missing, or the platform does not support the step metadata |
| Sign-up fails with `INCODE-65009` | The onboarding client does not create an identity |
| Login fails with `INCODE-60001` | The user signed up without the Incode step, or the link was removed |
| Incode rejects the `login_hint` | The face authentication client is not configured for the identity id as login hint |
| Redirect URI mismatch at Incode | The redirect URI registered on the Incode client differs from the one on the connection |
