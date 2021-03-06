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

import com.amplifyframework.api.aws.AuthorizationType;

/**
 * Auth mode strategy that always returns the auth mode provided to its constructor.
 */
public class DefaultAuthModeStrategy implements AuthModeStrategy {
    private final AuthorizationType defaultAuthMode;

    /**
     * Constructor that accepts the auth mode that will always be returned by the authModeFor method.
     * @param defaultAuthMode The auth mode that will be returned by this strategy.
     */
    public DefaultAuthModeStrategy(AuthorizationType defaultAuthMode) {
        this.defaultAuthMode = defaultAuthMode;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthorizationType authModeFor(String modelName, String operation) {
        return defaultAuthMode;
    }
}
