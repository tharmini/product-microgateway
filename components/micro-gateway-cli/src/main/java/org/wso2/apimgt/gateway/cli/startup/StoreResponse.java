package org.wso2.apimgt.gateway.cli.startup;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.apimgt.gateway.cli.constants.RESTServiceConstants;
import org.wso2.apimgt.gateway.cli.utils.RESTAPIUtils;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 *  This class is to load the response get by public Petstore API against id into memory.
 */
public class StoreResponse {
    private static final Logger log = LoggerFactory.getLogger("ballerina");
    private static Map<Integer, String> responseHashMap = new HashMap<>();

    public static void readDataToMemory() {
        URL url;
        HttpURLConnection urlConn = null;
        try {
            for (int i = 2; i < 3; i++) {
                String urlStr = "https://petstore.swagger.io/v2/pet/" + i;
                url = new URL(urlStr);
                urlConn = (HttpURLConnection) url.openConnection();
                urlConn.setDoOutput(true);
                urlConn.setRequestMethod(RESTServiceConstants.GET);
                int responseCode = urlConn.getResponseCode();
                log.debug("Response code: {}", responseCode);
                if (responseCode == 200) {
                    String responseStr = RESTAPIUtils.getResponseString(urlConn.getInputStream());
                    responseHashMap.put(i,responseStr);
                    log.trace("Response body: {}", responseStr);
                } else {
                    throw new Exception("Error occurred " + responseCode);
                }
            }
        } catch (IOException e) {

            // handle exception
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (urlConn != null) {
                urlConn.disconnect();
            }
        }
    }
}
