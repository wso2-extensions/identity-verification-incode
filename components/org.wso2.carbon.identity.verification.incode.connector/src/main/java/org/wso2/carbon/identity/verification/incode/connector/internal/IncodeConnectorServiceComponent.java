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

package org.wso2.carbon.identity.verification.incode.connector.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.verification.incode.connector.IncodeAuthenticator;
import org.wso2.carbon.identity.verification.incode.connector.IncodeExecutor;
import org.wso2.carbon.idp.mgt.IdpManager;

/**
 * Registers the Incode authenticator (login) and executor (registration flow).
 */
@Component(
        name = "identity.verification.incode.connector",
        immediate = true)
public class IncodeConnectorServiceComponent {

    private static final Log LOG = LogFactory.getLog(IncodeConnectorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            ctxt.getBundleContext().registerService(
                    ApplicationAuthenticator.class.getName(), new IncodeAuthenticator(), null);
            ctxt.getBundleContext().registerService(Executor.class.getName(), new IncodeExecutor(), null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Incode connector bundle activated.");
            }
        } catch (Exception e) {
            LOG.fatal("Error registering the Incode connector services.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Incode connector bundle deactivated.");
        }
    }

    @Reference(
            name = "FederatedAssociationManager",
            service = FederatedAssociationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetFederatedAssociationManager")
    protected void setFederatedAssociationManager(FederatedAssociationManager federatedAssociationManager) {

        IncodeConnectorDataHolder.setFederatedAssociationManager(federatedAssociationManager);
    }

    protected void unsetFederatedAssociationManager(FederatedAssociationManager federatedAssociationManager) {

        IncodeConnectorDataHolder.setFederatedAssociationManager(null);
    }

    @Reference(
            name = "IdentityProviderManager",
            service = IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdpManager")
    protected void setIdpManager(IdpManager idpManager) {

        IncodeConnectorDataHolder.setIdpManager(idpManager);
    }

    protected void unsetIdpManager(IdpManager idpManager) {

        IncodeConnectorDataHolder.setIdpManager(null);
    }
}
