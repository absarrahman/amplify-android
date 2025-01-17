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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.amplifyframework.api.ApiException;
import com.amplifyframework.api.aws.ApiAuthProviders;
import com.amplifyframework.api.aws.AppSyncGraphQLRequest;
import com.amplifyframework.api.aws.AuthorizationType;
import com.amplifyframework.api.aws.sigv4.AppSyncV4Signer;
import com.amplifyframework.api.aws.sigv4.CognitoUserPoolsAuthProvider;
import com.amplifyframework.api.aws.sigv4.DefaultCognitoUserPoolsAuthProvider;
import com.amplifyframework.api.graphql.GraphQLRequest;
import com.amplifyframework.core.Amplify;
import com.amplifyframework.logging.Logger;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.mobile.client.AWSMobileClient;

import java.util.Objects;

import okhttp3.Request;

/**
 * Factory class that creates instances of different implementations of {@link RequestDecorator}s.
 */
public final class ApiRequestDecoratorFactory {
    private static final Logger LOG = Amplify.Logging.forNamespace("amplify:aws-api");
    private static final String AUTH_DEPENDENCY_PLUGIN_KEY = "awsCognitoAuthPlugin";
    private static final RequestDecorator NO_OP_REQUEST_DECORATOR = new RequestDecorator() {
        @Override
        public Request decorate(Request request) {
            return request;
        }
    };

    private final ApiAuthProviders apiAuthProviders;
    private final String region;
    private final AuthorizationType defaultAuthorizationType;
    private final String apiKey;

    /**
     * Constructor that accepts the API auth providers to be used with their respective request decorator.
     * @param apiAuthProviders An instance with fully configured auth providers for use when signing requests.
     * @param defaultAuthorizationType The authorization type to use as default.
     * @param region The AWS region where the API is deployed.
     */
    public ApiRequestDecoratorFactory(@NonNull ApiAuthProviders apiAuthProviders,
                                      @NonNull AuthorizationType defaultAuthorizationType,
                                      @NonNull String region) {
        this(apiAuthProviders, defaultAuthorizationType, region, null);
    }

    /**
     * Constructor that accepts the API auth providers to be used with their respective request decorator.
     * @param apiAuthProviders An instance with fully configured auth providers for use when signing requests.
     * @param defaultAuthorizationType The authorization type to use as default.
     * @param region The AWS region where the API is deployed.
     * @param apiKey The API key to use for APIs with API_KEY authentication type.
     */
    public ApiRequestDecoratorFactory(@NonNull ApiAuthProviders apiAuthProviders,
                                      @NonNull AuthorizationType defaultAuthorizationType,
                                      @NonNull String region,
                                      @Nullable String apiKey) {
        this.apiAuthProviders = Objects.requireNonNull(apiAuthProviders);
        this.defaultAuthorizationType = Objects.requireNonNull(defaultAuthorizationType);
        this.region = Objects.requireNonNull(region);
        this.apiKey = apiKey;
    }

    /**
     * Return the appropriate request decorator after inspecting the request.
     * @param graphQLRequest The graphQL request sent to the API.
     * @return The request decorator.
     * @throws ApiException If it's unable to retrieve the decorator for the given request.
     */
    public RequestDecorator fromGraphQLRequest(GraphQLRequest<?> graphQLRequest) throws ApiException {
        // Start with the default auth type.
        AuthorizationType authType = defaultAuthorizationType;
        // If it is an instance of AppSyncGraphQLRequest AND
        // the request's authorization type is not null
        if (graphQLRequest instanceof AppSyncGraphQLRequest<?>
            && ((AppSyncGraphQLRequest<?>) graphQLRequest).getAuthorizationType() != null) {
            authType = ((AppSyncGraphQLRequest<?>) graphQLRequest).getAuthorizationType();
        }
        return forAuthType(authType);
    }

    /**
     * Given a authorization type, it returns the appropriate request decorator.
     * @param authorizationType the authorization type to be used for the request.
     * @return the appropriate request decorator for the given authorization type.
     * @throws ApiException if unable to get a request decorator.
     */
    public RequestDecorator forAuthType(@NonNull AuthorizationType authorizationType) throws ApiException {
        switch (authorizationType) {
            case AMAZON_COGNITO_USER_POOLS:
                // Note that if there was no user-provided cognito provider passed in to initialize
                // the API plugin, we will try to default to using the DefaultCognitoUserPoolsAuthProvider.
                //  If that fails, we then have no choice but to bubble up the error.
                CognitoUserPoolsAuthProvider cognitoUserPoolsAuthProvider =
                        apiAuthProviders.getCognitoUserPoolsAuthProvider() != null ?
                                apiAuthProviders.getCognitoUserPoolsAuthProvider() :
                                new DefaultCognitoUserPoolsAuthProvider();
                // By calling getLatestAuthToken() here instead of inside the lambda block, makes the exception
                // handling a little bit cleaner. If getLatestAuthToken() is called from inside the lambda expression
                // below, we'd have to surround it with a try catch. By doing it this way, if there's a problem,
                // the ApiException will just be bubbled up. Same for OPENID_CONNECT.
                final String token = cognitoUserPoolsAuthProvider.getLatestAuthToken();
                return new JWTTokenRequestDecorator(() -> token);
            case OPENID_CONNECT:
                if (apiAuthProviders.getOidcAuthProvider() == null) {
                    throw new ApiException("Attempting to use OPENID_CONNECT authorization " +
                            "without an OIDC provider.",
                            "Configure an OidcAuthProvider when initializing the API plugin.");
                }
                final String oidcToken = apiAuthProviders.getOidcAuthProvider().getLatestAuthToken();
                return new JWTTokenRequestDecorator(() -> oidcToken);
            case API_KEY:
                if (apiAuthProviders.getApiKeyAuthProvider() != null) {
                    return new ApiKeyRequestDecorator(apiAuthProviders.getApiKeyAuthProvider());
                } else if (apiKey != null) {
                    return new ApiKeyRequestDecorator(() -> apiKey);
                } else {
                    throw new ApiException("Attempting to use API_KEY authorization without an API key provider or " +
                            "an API key in the config file",
                            "Verify that an API key is in the config file or an " +
                                    "ApiKeyAuthProvider is setup during the API plugin initialization.");
                }
            case AWS_IAM:
                AWSCredentialsProvider credentialsProvider = apiAuthProviders.getAWSCredentialsProvider() != null
                        ? apiAuthProviders.getAWSCredentialsProvider()
                        : getDefaultCredentialsProvider();
                AppSyncV4Signer appSyncV4Signer = new AppSyncV4Signer(region);
                return new IamRequestDecorator(appSyncV4Signer, credentialsProvider);
            case NONE:
            default:
                return NO_OP_REQUEST_DECORATOR;
        }
    }

    private AWSCredentialsProvider getDefaultCredentialsProvider() throws ApiException {
        // Obtains AWSMobileClient from Auth Category.
        // Throw if AWSCognitoAuthPlugin not configured.
        try {
            return (AWSMobileClient) Amplify.Auth.getPlugin(AUTH_DEPENDENCY_PLUGIN_KEY).getEscapeHatch();
        } catch (IllegalStateException exception) {
            throw new ApiException("Attempting to use AWS_IAM authorization without " +
                    "an AWS credentials provider.",
                    "Configure an AWSCredentialsProvider when initializing the API plugin or register" +
                            "an instance of AWSCognitoAuthPlugin to Amplify.");
        }
    }
}
