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
 * Defines an interface to be used by the API plugin when determining which API to use.
 */
public interface AuthModeStrategy {

    /**
     * Based on the provided parameters, this function should return the authorization type
     * that the API plugin should use when attempting to make a request.
     * @param modelName The name of the model for the request.
     * @param operation The operation being performed (read, create, update, delete)
     * @return The authorization type that the API plugin should try to use.
     */
    AuthorizationType authModeFor(String modelName, String operation);
}
