// Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file   except
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
import ballerina/runtime;
import ballerina/stringutils;
import ballerinax/java;


# Representation of the mutual ssl handler
#
public type MutualSSLHandler object {
    *http:InboundAuthHandler;

    # Checks if the request can be authenticated with the Bearer Auth header.
    #
    # + req - The `Request` instance.
    # + return - Returns `true` if can be authenticated. Else, returns `false`.
    public function canProcess(http:Request req) returns @tainted boolean {
        return true;
    }

    # Authenticates the incoming request knowing that mutual ssl has happened at the trasnport layer.
    #
    # + req - The `Request` instance.
    # + return - Returns `true` if authenticated successfully. Else, returns `false`
    # or the `AuthenticationError` in case of an error.
    public function process(http:Request req) returns boolean | http:AuthenticationError {
        string|error mutualSSLVerifyClient = getMutualSSL();
        if (mutualSSLVerifyClient is string && stringutils:equalsIgnoreCase(MANDATORY, mutualSSLVerifyClient) 
                && req.mutualSslHandshake[STATUS] != PASSED ) {
            if (req.mutualSslHandshake[STATUS] == FAILED) {
                printDebug(KEY_AUTHN_FILTER, "MutualSSL handshake status: FAILED");
            }
            // provided more generic error code to avoid security issues.
            setErrorMessageToInvocationContext(API_AUTH_INVALID_CREDENTIALS); 
            return prepareAuthenticationError("Failed to authenticate with MutualSSL handler");


        }

        string trustStorePath = getConfigValue(LISTENER_CONF_INSTANCE_ID, TRUST_STORE_PATH, DEFAULT_TRUST_STORE_PATH);
        string trustStorePassword = getConfigValue(LISTENER_CONF_INSTANCE_ID, TRUST_STORE_PASSWORD, DEFAULT_TRUST_STORE_PASSWORD);




        if (req.mutualSslHandshake[STATUS] == PASSED) {
            string? cert = req.mutualSslHandshake["base64EncodedCert"];
            printDebug("decoded cert ****************wwwwwwwww", cert.toString());
            if (req.hasHeader("base64EncodedCert")) {
                string headerValue = req.getHeader("base64EncodedCert").toLowerAscii();
                if(headerValue != "") {

                    //boolean|error decodedCert =  getcert(cert.toString(),trustStorePath.toString(),trustStorePassword.toString());
                    boolean|error isCertexistInTrustStore =  isExistCert(headerValue,trustStorePath.toString(),trustStorePassword.toString());
                    //printDebug("decoded cert ****************", decodedCert.toString());
                }

            }
            else{
                handle|error serial_number = getSerialNumber(cert.toString());

            }
            printDebug(req.toString(), "req******************");
            printDebug(KEY_AUTHN_FILTER, "MutualSSL handshake status: PASSED");
            runtime:InvocationContext invocationContext = runtime:getInvocationContext();
            printDebug(invocationContext.toString(), "invocationContext***************");
            doMTSLFilterRequest(req, invocationContext); 
        }
        return true;
    }
};


function doMTSLFilterRequest(http:Request request, runtime:InvocationContext context) {
    runtime:InvocationContext invocationContext = runtime:getInvocationContext();
    AuthenticationContext authenticationContext = {};
    printDebug(KEY_AUTHN_FILTER, "Processing request via MutualSSL filter.");

    context.attributes[IS_SECURED] = true;
    int startingTime = getCurrentTimeForAnalytics();
    context.attributes[REQUEST_TIME] = startingTime;
    context.attributes[FILTER_FAILED] = false;
    //Set authenticationContext data
    authenticationContext.authenticated = true;
    authenticationContext.username = USER_NAME_UNKNOWN;
    invocationContext.attributes[KEY_TYPE_ATTR] = authenticationContext.keyType;
    context.attributes[AUTHENTICATION_CONTEXT] = authenticationContext;
}


public function getcert(string cert,string trustStorePath,string trustStorePassword) returns boolean|error {
    handle cert1 = java:fromString(cert);
    handle trustStorePath1 = java:fromString(trustStorePath);
    handle trustStorePassword1 = java:fromString(trustStorePassword);
    boolean|error certt = jgetcert(cert1,trustStorePath1,trustStorePassword1);
    return certt;
}

function jgetcert(handle cert, handle trustStorePath,handle trustStorePassword) returns boolean|error = @java:Method {
    name: "invokegetcert",
    class: "org.wso2.micro.gateway.core.mutualssl.MutualsslInvoker"
} external;

public function getSerialNumber(string cert) returns handle|error{
    handle cert1 = java:fromString(cert);
    handle|error serial_number = jgetSerialNumber(cert1);
    return serial_number;
}

public function jgetSerialNumber(handle cert) returns handle|error = @java:Method {
    name: "getSerialNumberOfCert",
    class: "org.wso2.micro.gateway.core.mutualssl.MutualsslInvoker"
} external;

public function isExistCert(string cert,string trustStorePath,string trustStorePassword) returns boolean|error {
    handle cert1 = java:fromString(cert);
    handle trustStorePath1 = java:fromString(trustStorePath);
    handle trustStorePassword1 = java:fromString(trustStorePassword);
    boolean|error certt = jisExistCert(cert1,trustStorePath1,trustStorePassword1);
    return certt;
}

function jisExistCert(handle cert, handle trustStorePath,handle trustStorePassword) returns boolean|error = @java:Method {
    name: "isExistCert",
    class: "org.wso2.micro.gateway.core.ssl.MutualSsl"
} external;