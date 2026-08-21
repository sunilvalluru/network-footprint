// LegacyClient.java - exercises the code-artifact exclusion path.
// The package/import lines below LOOK like domains but are Java namespaces,
// NOT network endpoints. The analyzer should EXCLUDE them from the inventory.
package com.acme.sample.legacy;

import org.springframework.boot.SpringApplication;
import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.http.HttpClient;

public class LegacyClient {

    // Real external endpoint (should be DETECTED - inbound):
    private static final String STATUS_URL = "https://status.acme-service.com/v1/health";

    public String checkStatus() {
        RestTemplate rest = new RestTemplate();
        // IN: GET a status document
        return rest.getForObject(STATUS_URL, String.class);
    }
}
