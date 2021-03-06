// Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/http;
import ballerina/jwt;
import ballerina/runtime;

# Handle additional claims in JWT token and set them to invocation context.
# Then return check subscription is validated or not.
#
# + apiKeyToken - jwt token
# + payload - payload of jwt token
# + subscribedAPIList - subscribedAPIList array
# + validateAllowedAPIs - validate allowed APIs boolean value
# + return - subscribed APIs validated or not
public function handleSubscribedAPIs(string apiKeyToken, jwt:JwtPayload payload, json[] subscribedAPIList,
        boolean validateAllowedAPIs) returns boolean {

    runtime:InvocationContext invocationContext = runtime:getInvocationContext();
    //invocation context
    AuthenticationContext authenticationContext = {};
    authenticationContext.apiKey = apiKeyToken;
    authenticationContext.callerToken = apiKeyToken;
    // if validateAllowedAPIs is false, then set authenticated to true.
    // Then if validateAllowedAPIs is true only set authenticated true after validating APIs.
    authenticationContext.authenticated = !validateAllowedAPIs;

    string? username = payload?.sub;
    if (username is string) {
        authenticationContext.username = username;
    }

    map<json>? customClaims = payload?.customClaims;
    //set keytype
    if (customClaims is map<json> && customClaims.hasKey(KEY_TYPE)) {
        json keyType = customClaims.get(KEY_TYPE);
        authenticationContext.keyType = keyType.toString();
    }
    invocationContext.attributes[KEY_TYPE_ATTR] = authenticationContext.keyType;

    //set consumer key
    if (customClaims is map<json> && customClaims.hasKey(CONSUMER_KEY)) {
        json consumerKey = customClaims.get(CONSUMER_KEY);
        authenticationContext.consumerKey = consumerKey.toString();
    }

    //set application attributes if present in token
    if (customClaims is map<json> && customClaims.hasKey(APPLICATION)) {
        json? application = customClaims.get(APPLICATION);
        if (application is map<json>) {
            if (application.hasKey("id")) {
                authenticationContext.applicationId = application.id.toString();
            }
            if (application.hasKey("name")) {
                authenticationContext.applicationName = application.name.toString();
            }
            if (application.hasKey("tier")) {
                authenticationContext.applicationTier = application.tier.toString();
            }
            if (application.hasKey("owner")) {
                authenticationContext.subscriber = application.owner.toString();
            }
        }
    }
    //validate allowed apis
    APIConfiguration? apiConfig = apiConfigAnnotationMap[<string>invocationContext.attributes[http:SERVICE_NAME]];
    if (apiConfig is APIConfiguration) {
        string apiName = apiConfig.name;
        string apiVersion = apiConfig.apiVersion;
        int l = subscribedAPIList.length();
        int index = 0;
        while (index < l) {
            var subscription = subscribedAPIList[index];
            if (subscription.name.toString() == apiName && subscription.'version.toString() == apiVersion) {
                // Successfully validated the API. Then set authenticated to true.
                authenticationContext.authenticated = true;
                if (isDebugEnabled) { 
                    printDebug(JWT_UTIL, "Found a matching allowed api with name:" + subscription.name.toString()
                        + " version:" + subscription.'version.toString());
                }

                //set throttling attribs if present
                if (subscription.subscriptionTier is json) {
                    authenticationContext.tier = subscription.subscriptionTier.toString();
                }
                if (subscription.publisher is json) {
                    authenticationContext.apiPublisher = subscription.publisher.toString();
                }
                if (subscription.subscriberTenantDomain is json) {
                    authenticationContext.subscriberTenantDomain = subscription.subscriberTenantDomain.toString();
                }
                if (isDebugEnabled) { 
                    printDebug(JWT_UTIL, "Set username : " + authenticationContext.username + ", keytype : " 
                    + authenticationContext.keyType + ", consumer key : " + authenticationContext.consumerKey 
                    + ", application ID : " + authenticationContext.applicationId + ", application name : " 
                    + authenticationContext.applicationName + ", application tier : " + authenticationContext.applicationTier 
                    + ", application owner : " + authenticationContext.subscriber + ", application tier : " 
                    + authenticationContext.tier + ", apiTier : " + authenticationContext.apiTier 
                    + ", apiPublisher : " + authenticationContext.apiPublisher + ", subscriberTenantDomain : " 
                    + authenticationContext.subscriberTenantDomain);
                }
                invocationContext.attributes[AUTHENTICATION_CONTEXT] = authenticationContext;
                return true;
            }
            index += 1;
        }
    }
    if (isDebugEnabled) { 
        printDebug(JWT_UTIL, "Set username : " + authenticationContext.username + ", keytype : " 
        + authenticationContext.keyType + ", consumer key : " + authenticationContext.consumerKey 
        + ", application ID : " + authenticationContext.applicationId + ", application name : " 
        + authenticationContext.applicationName + ", application tier : " + authenticationContext.applicationTier 
        + ", application owner : " + authenticationContext.subscriber + ", application tier : " 
        + authenticationContext.tier + ", apiTier : " + authenticationContext.apiTier 
        + ", apiPublisher : " + authenticationContext.apiPublisher + ", subscriberTenantDomain : " 
        + authenticationContext.subscriberTenantDomain);
    }
    invocationContext.attributes[AUTHENTICATION_CONTEXT] = authenticationContext;
    return false;
}

public function getDecodedJWTPayload(string jwtToken) returns @tainted (jwt:JwtPayload | error) {
    //decode jwt
    var cachedJwt = trap <jwt:CachedJwt>jwtCache.get(jwtToken);
    if (cachedJwt is jwt:CachedJwt) {
        printDebug(JWT_UTIL, "jwt found from the jwt cache");
        return cachedJwt.jwtPayload;

    } else {
        [jwt:JwtHeader, jwt:JwtPayload] | jwt:Error decodedJWT = jwt:decodeJwt(jwtToken);
        if (decodedJWT is error) {
            printDebug(JWT_UTIL, "Error while decoding the JWT token");
            return error("Error while decoding the JWT token");
        }
        [jwt:JwtHeader, jwt:JwtPayload][jwtHeader, payload] = <[jwt:JwtHeader,jwt:JwtPayload]> decodedJWT;
        return payload;
    }
}
