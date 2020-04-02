/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.micro.gateway.core.mapping;

import org.ballerinalang.jvm.values.MapValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.micro.gateway.jwttransformer.JWTTransformer;


/**
 * This class Class to dynamically invoke the transformer.
 */
public class MappingInvoker {

    private static final Logger log = LoggerFactory.getLogger("ballerina");
    private static JWTTransformer jwtTransformer;

    public static String loadMappingClass(String className) {
        try {
            Class mappingClass = MappingInvoker.class.getClassLoader().loadClass(className);
            jwtTransformer = (JWTTransformer) mappingClass.newInstance();
            return className;
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            log.error("Error while loading the jwttransformer class: " + className, e);
        }
        return className;
    }

    public static MapValue transformJWT(MapValue claims) {
        MapValue claimSet = jwtTransformer.transformJWT(claims);
        return claimSet;
    }
}