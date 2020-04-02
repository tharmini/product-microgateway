// Copyright (c) 2020 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.micro.gateway.jwttransformer;

import org.ballerinalang.jvm.values.ArrayValueImpl;
import org.ballerinalang.jvm.values.MapValue;

/**
 * This class is for default Jwt transformer.
 */
public class DefaultJWTTransformer implements JWTTransformer {

    @Override
    public MapValue transformJWT(MapValue jwtClaims) {
        String scope = "";
        MapValue claimSet = jwtClaims;
        int sizeOfClaims = claimSet.size();
        String name = claimSet.get("scope").getClass().getName();
        if (claimSet.containsKey("scope")) {
            if (claimSet.get("scope") instanceof ArrayValueImpl) {
                for (int i = 0; i < ((ArrayValueImpl) claimSet.get("scope")).size(); i++) {
                    scope += ((ArrayValueImpl) claimSet.get("scope")).getString(i) + " ";
                }
                scope = scope.trim();
            }
            claimSet.put("scope", scope);
        }
        return claimSet;
    }
}
