/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amplifyframework.api.aws.auth;

import com.amplifyframework.api.aws.ApiAuthProviders;
import com.amplifyframework.api.aws.AuthorizationType;
import com.amplifyframework.core.Amplify;
import com.amplifyframework.core.model.AuthRule;
import com.amplifyframework.core.model.AuthStrategy;
import com.amplifyframework.core.model.ModelOperation;
import com.amplifyframework.core.model.ModelSchema;
import com.amplifyframework.logging.Logger;

import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Auth mode strategy that uses auth rule metadata from generated models in order to determine which
 * auth mode to use for a given request.
 */
public class MultiAuthModeStrategy implements AuthModeStrategy {
    private static final Logger LOG = Amplify.Logging.forNamespace("amplify:aws-api");
    private static final List<AuthStrategy> STRATEGY_PRIORITY = Arrays.asList(AuthStrategy.OWNER,
                                                                              AuthStrategy.GROUPS,
                                                                              AuthStrategy.PRIVATE,
                                                                              AuthStrategy.PUBLIC);
    private final ApiAuthProviders providers;
    //TODO: Use enums for keys. Right now we have a couple different enums, so we may need to consolidate.
    private Map<String, Set<AuthorizationType>> authTypeCache;

    /**
     * Constructor that accepts a list of model schemas and API auth providers for the
     * associated API.
     * @param modelSchemas List of model schemas for the API.
     * @param providers Auth providers available to the API.
     */
    public MultiAuthModeStrategy(List<ModelSchema> modelSchemas, ApiAuthProviders providers) {
        this.providers = providers;
        configure(modelSchemas);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthorizationType authModeFor(String modelName, String operation) {
        LOG.info("Getting auth mode for " + modelName + " " + operation);
        String key = getKey(modelName, operation);
        Set<AuthorizationType> authorizationTypes = authTypeCache.get(key);
        for (AuthorizationType authorizationType : authorizationTypes) {
            if (isUsable(authorizationType)) {
                return authorizationType;
            }
        }
        return AuthorizationType.NONE;
    }

    private boolean isUsable(AuthorizationType authorizationType) {
        switch (authorizationType) {
            case AMAZON_COGNITO_USER_POOLS:
                return providers.getCognitoUserPoolsAuthProvider() != null &&
                        Amplify.Auth.getCurrentUser() != null;
            case AWS_IAM:
                return providers.getAWSCredentialsProvider() != null;
            case API_KEY:
                return providers.getApiKeyAuthProvider() != null;
            default:
                return false;
        }
    }

    private void configure(List<ModelSchema> modelSchemas) {
        authTypeCache = new HashMap<>();
        for (ModelSchema modelSchema : modelSchemas) {
            for (ModelOperation operation : ModelOperation.values()) {
                List<AuthRule> applicableRules = modelSchema.getApplicableRules(operation);
                Set<AuthorizationType> modelAuthTypes = getProviderSequenceForRules(applicableRules);
                //TODO: Poor man's cache key.
                authTypeCache.put(getKey(modelSchema.getName(), operation.name()), modelAuthTypes);
            }
        }
    }

    /**
     * Given a list of auth rules, this functions sorts those rules according to the
     * priority established by this strategy, then returns a ordered set of of auth providers
     * associated with each rule.
     * @param authRules List of auth rules for a type.
     * @return A set of auth providers sorted by priority.
     */
    private Set<AuthorizationType> getProviderSequenceForRules(List<AuthRule> authRules) {
        Set<AuthorizationType> result = new LinkedHashSet<>();

        authRules.sort(new Comparator<AuthRule>() {
            @Override
            public int compare(AuthRule authRule1, AuthRule authRule2) {
                Integer o1Priority = Integer.valueOf(STRATEGY_PRIORITY.indexOf(authRule1.getAuthStrategy()));
                Integer o2Priority = Integer.valueOf(STRATEGY_PRIORITY.indexOf(authRule2.getAuthStrategy()));
                return o1Priority.compareTo(o2Priority);
            }
        });

        for (AuthRule rule : authRules) {
            result.add(getAuthTypeForStrategy(rule.getAuthStrategy()));
        }

        return result;
    }

    /**
     * For now, statically map this since Android doesn't have the provider in the
     * generated code.
     * @param strategy The auth strategy used to determine the appropriate provider.
     * @return An authorization type.
     */
    private AuthorizationType getAuthTypeForStrategy(AuthStrategy strategy) {
        switch (strategy) {
            case OWNER:
            case GROUPS:
                return AuthorizationType.AMAZON_COGNITO_USER_POOLS;
            case PRIVATE:
                return AuthorizationType.AWS_IAM;
            case PUBLIC:
                return AuthorizationType.API_KEY;
            default:
                return AuthorizationType.NONE;
        }
    }

    private String getKey(String modelName, String operation) {
        //TODO: Poor man's cache key
        return modelName + "|" + operation;
    }
}
