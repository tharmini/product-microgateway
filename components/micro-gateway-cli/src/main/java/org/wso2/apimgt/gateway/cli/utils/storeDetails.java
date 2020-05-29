package org.wso2.apimgt.gateway.cli.utils;


import org.apache.http.HttpResponse;


import java.util.HashMap;
import java.util.Map;

public class storeDetails {
    Map<String, String> headers = new HashMap<>();
    HttpResponse response = HttpClientRequest.doGet(getServiceURLHttp("petstore/v2/pet/findByStatus"), new HashMap<>());
}


