// Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import ballerina/auth;
import ballerina/jwt;
import ballerina/runtime;
import ballerina/stringutils;
import ballerina/config;
import ballerina/io;

# Represents inbound JWT auth provider.
#
# + jwtValidatorConfig - JWT validator configurations
# + inboundJwtAuthProvider - Reference to b7a inbound auth provider
# + subscriptionValEnabled - Validate subscription
public type JwtAuthProvider object {
    *auth:InboundAuthProvider;

    public jwt:JwtValidatorConfig jwtValidatorConfig;
    public jwt:InboundJwtAuthProvider inboundJwtAuthProvider;
    public boolean subscriptionValEnabled;

    # Provides authentication based on the provided JWT token.
    #
    # + jwtValidatorConfig - JWT validator configurations
    # + subscriptionValEnabled - Validate subscription
    public function __init(jwt:JwtValidatorConfig jwtValidatorConfig, boolean subscriptionValEnabled) {
        self.jwtValidatorConfig = jwtValidatorConfig;
        self.inboundJwtAuthProvider = new (jwtValidatorConfig);
        self.subscriptionValEnabled = subscriptionValEnabled;
    }


    public function authenticate(string credential) returns @tainted (boolean | auth:Error) {
        //Start a span attaching to the system span.
        int | error | () spanIdAuth = startSpan(JWT_PROVIDER_AUTHENTICATE);
        var handleVar = self.inboundJwtAuthProvider.authenticate(credential);
        //finishing span
        finishSpan(JWT_PROVIDER_AUTHENTICATE, spanIdAuth);
        if (handleVar is boolean) {
            if (!handleVar) {
                setErrorMessageToInvocationContext(API_AUTH_INVALID_CREDENTIALS);
                return handleVar;
            }

            boolean isBlacklisted = false;
            string? jti = "";
            runtime:InvocationContext invocationContext = runtime:getInvocationContext();
            runtime:AuthenticationContext? authContext = invocationContext?.authenticationContext;
            runtime:InvocationContext edited_invocationContext=doMappingContext(invocationContext);
            runtime:Principal? principal2 = edited_invocationContext["principal"];
            runtime:Principal? principal = invocationContext["principal"];
            if (principal is runtime:Principal && principal2 is runtime:Principal) {
                printDebug( edited_invocationContext["principal"].toString(), " invocationContext[principa]**************************");
                principal=principal2;
             }
            printDebug( invocationContext["principal"].toString(), " invocationContext[principa]**************************");
            printDebug( edited_invocationContext["principal"].toString(), " edited_invocationContextinvocationContext[principa]**************************");
            printDebug(edited_invocationContext.toString(), "edited_invocationContext****************************");

            if (authContext is runtime:AuthenticationContext) {
                string? jwtToken = authContext?.authToken;
                if (jwtToken is string) {
                    boolean isGRPC = invocationContext.attributes.hasKey(IS_GRPC);
                    //Start a new child span for the span.
                    int | error | () spanIdCache = startSpan(JWT_CACHE);
                    var cachedJwt = trap <jwt:CachedJwt>jwtCache.get(jwtToken);
                    //finishing span
                    finishSpan(JWT_CACHE, spanIdCache);
                    if (cachedJwt is jwt:CachedJwt) {
                        printDebug(KEY_JWT_AUTH_PROVIDER, "jwt found from the jwt cache");
                        jwt:JwtPayload jwtPayloadFromCache = cachedJwt.jwtPayload;
                        jti = jwtPayloadFromCache["jti"];
                        if (jti is string) {
                            printDebug(KEY_JWT_AUTH_PROVIDER, "jti claim found in the jwt");
                            printDebug(KEY_JWT_AUTH_PROVIDER, "Checking for the JTI in the gateway invalid revoked token map.");
                            var status = retrieveFromRevokedTokenMap(jti);
                            if (status is boolean) {
                                if (status) {
                                    printDebug(KEY_JWT_AUTH_PROVIDER, "JTI token found in the invalid token map.");
                                    isBlacklisted = true;
                                } else {
                                    printDebug(KEY_JWT_AUTH_PROVIDER, "JTI token not found in the invalid token map.");
                                    isBlacklisted = false;
                                }
                            } else {
                                printDebug(KEY_JWT_AUTH_PROVIDER, "JTI token not found in the invalid token map.");
                                isBlacklisted = false;
                            }

                            if (isBlacklisted) {
                                printDebug(KEY_JWT_AUTH_PROVIDER, "JWT Authentication Handler value for, is token black listed: " + isBlacklisted.toString());
                                printDebug(KEY_JWT_AUTH_PROVIDER, "JWT Token is revoked");
                                setErrorMessageToInvocationContext(API_AUTH_INVALID_CREDENTIALS);
                                return false;
                            }
                        } else {
                            printDebug(KEY_JWT_AUTH_PROVIDER, "jti claim not found in the jwt");
                        }
                        return validateSubscriptions(jwtToken, cachedJwt.jwtPayload, self.subscriptionValEnabled, isGRPC);
                    } 
                    printDebug(KEY_JWT_AUTH_PROVIDER, "jwt not found in the jwt cache");
                    (jwt:JwtPayload | error) payload = getDecodedJWTPayload(jwtToken);
                    if (payload is jwt:JwtPayload) {
                        return validateSubscriptions(jwtToken, payload, self.subscriptionValEnabled, isGRPC);
                    }
                }
            }
            return handleVar;
        } else {
            setErrorMessageToInvocationContext(API_AUTH_INVALID_CREDENTIALS);
            return prepareError("Failed to authenticate with jwt auth provider.", handleVar);
        }
    }
};

public function validateSubscriptions(string jwtToken, jwt:JwtPayload payload, boolean subscriptionValEnabled, boolean isGRPC) 
        returns @tainted (boolean | auth:Error) {
    boolean subscriptionValidated = false;
    json subscribedAPIList = [];
    map<json>? customClaims = payload?.customClaims;
    //get allowed apis
    if (customClaims is map<json> && customClaims.hasKey(SUBSCRIBED_APIS)) {
        printDebug(KEY_JWT_AUTH_PROVIDER, "subscribedAPIs claim found in the jwt.");
        subscribedAPIList = customClaims.get(SUBSCRIBED_APIS);
    }
    if (subscribedAPIList is json[]) {
        if (subscriptionValEnabled && subscribedAPIList.length() < 1) {
            setErrorMessageToInvocationContext(API_AUTH_FORBIDDEN);
            return prepareError("SubscribedAPI list is empty.");
        }
        subscriptionValidated = handleSubscribedAPIs(jwtToken, payload, subscribedAPIList, subscriptionValEnabled);
        if (subscriptionValidated || !subscriptionValEnabled || isGRPC) {
            printDebug(KEY_JWT_AUTH_PROVIDER, "Subscriptions validation passed.");
            return true;
        } else { 
            setErrorMessageToInvocationContext(API_AUTH_FORBIDDEN);
            return prepareError("Subscriptions validation failed.");
        }
    }
    setErrorMessageToInvocationContext(API_AUTH_FORBIDDEN);
    return prepareError("Failed to decode the JWT.");
}



public function doMappingContext(runtime:InvocationContext invocationContext) returns @tainted runtime:InvocationContext {
    //decode jwt
    string? payloadissuer=invocationContext["principal"]["userId"];
    if(payloadissuer is  string) {
        string[] result = stringutils:split(payloadissuer, ":");
        payloadissuer=result[0].concat(":",result[1],":",result[2]);
        printDebug(payloadissuer, "payloadissuer***************************************.");
    }
    map<anydata>[] | error jwtIssuers = map<anydata>[].constructFrom(config:getAsArray(JWT_INSTANCE_ID));
        if (jwtIssuers is map<anydata>[] && jwtIssuers.length() > 0) {
            foreach map<anydata> jwtIssuer in jwtIssuers {
                   string issuer=getDefaultStringValue(jwtIssuer[ISSUER], DEFAULT_JWT_ISSUER);
                   if (issuer==payloadissuer){
                        map<anydata> claims = <map<anydata>>jwtIssuer["claims"];
                        printDebug(claims.toString(), "claims.........................");
                        printDebug(claims.length().toString(), "claims length.........................");
                        if (claims.length() > 0){
                            string[] keys = claims.keys();
                            foreach string key in keys {
                                string claimvalue = claims[key].toString(); //scps
                                map<any>? customClaims = invocationContext["principal"]["claims"];
                                if(customClaims is map<anydata>) {
                                io:println("customClaims is mapped.........................");
                                    if(customClaims.hasKey(claimvalue)) {
                                        customClaims[key] = customClaims[claimvalue];
                                        io:println(customClaims[key].toString(),"customClaims[key].........................");
                                        anydata removedElement = customClaims.remove(claimvalue);
                                     }
                                }
                            }
                        }
                   }
            }
        }
     return invocationContext;
}
