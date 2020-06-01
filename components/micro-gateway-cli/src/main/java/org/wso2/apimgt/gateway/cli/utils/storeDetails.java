package org.wso2.apimgt.gateway.cli.utils;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.apimgt.gateway.cli.constants.RESTServiceConstants;


import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class storeDetails {
    private static final Logger log = LoggerFactory.getLogger("ballerina");
    private static Map<Integer, String> responseHashMap = new HashMap<>();
    public static void readDataToMemory() {

        URL url;
        HttpsURLConnection urlConn = null;
        try {
            for (int i = 1; i <3 ; i++) {
                String urlStr = "https://localhost:9095/v2/pet/1";
                url = new URL(urlStr);

                urlConn = (HttpsURLConnection) url.openConnection();
                urlConn.setDoOutput(true);
                urlConn.setRequestMethod(RESTServiceConstants.GET);
                int responseCode = urlConn.getResponseCode();
                log.debug("Response code: {}", responseCode);

                if (responseCode == 200) {
                    ObjectMapper mapper = new ObjectMapper();
                    String responseStr = RESTAPIUtils.getResponseString(urlConn.getInputStream());
                    responseHashMap.put(i,responseStr);
                    log.trace("Response body: {}", responseStr);
                    // handle response
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


