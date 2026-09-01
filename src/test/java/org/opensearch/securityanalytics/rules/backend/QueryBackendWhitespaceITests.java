/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.backend;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.junit.Assume;
import org.opensearch.securityanalytics.rules.exceptions.CompositeSigmaErrors;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.test.OpenSearchTestCase;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.ConnectException;
import java.util.List;
import java.util.Map;

/**
 * Integration test verifying the generated phrase query matches documents in a local OpenSearch cluster.
 * Skips gracefully via {@link Assume} when the cluster is unreachable, so CI never fails without a local cluster.
 */
public class QueryBackendWhitespaceITests extends OpenSearchTestCase {

    private static final String OPENSEARCH_URL = "https://localhost:9200";
    private static final String INDEX = "syslog-audit";
    private static final String USERNAME = "admin";
    /** Read from env OPENSEARCH_IT_PASSWORD; falls back to the local-dev default. */
    private static final String PASSWORD =
        System.getenv("OPENSEARCH_IT_PASSWORD") != null
            ? System.getenv("OPENSEARCH_IT_PASSWORD")
            : "A3nonuser_";

    private static final Map<String, String> FIELD_MAPPINGS = Map.of(
        "attributes.message", "attributes.message"
    );

    /** Generates a phrase query for a spaced contains condition, posts it to the cluster, and asserts at least one hit. */
    public void testContainsPhraseQueryMatchesDocument() throws Exception {
        OSQueryBackend backend = new OSQueryBackend(FIELD_MAPPINGS, false, true);

        List<Object> queries;
        try {
            queries = backend.convertRule(SigmaRule.fromYaml(
                    "title: IT phrase test\n" +
                    "id: a1b2c3d4-0000-0000-0000-000000000001\n" +
                    "status: test\n" +
                    "level: medium\n" +
                    "description: Integration test for phrase query generation\n" +
                    "author: test\n" +
                    "date: 2024/01/01\n" +
                    "logsource:\n" +
                    "    category: test_category\n" +
                    "    product: test_product\n" +
                    "detection:\n" +
                    "    sel:\n" +
                    "        attributes.message|contains: \"admin Logging in success\"\n" +
                    "    condition: sel",
                    false));
        } catch (SigmaError | CompositeSigmaErrors e) {
            throw new RuntimeException("Sigma rule compilation failed", e);
        }

        String generatedQuery = queries.get(0).toString();
        assertEquals(
            "Backend must emit a quoted phrase for a spaced contains condition",
            "attributes.message: \"admin Logging in success\"",
            generatedQuery
        );

        // Build the query_string request body.
        String requestBody = "{\"query\":{\"query_string\":{\"query\":\"" +
            generatedQuery.replace("\"", "\\\"") + "\"}},\"track_total_hits\":true}";

        String responseBody;
        try {
            responseBody = executeSearch(INDEX, requestBody);
        } catch (ConnectException | SecurityException e) {
            // Cluster not available — skip so CI does not fail.
            Assume.assumeTrue("Local OpenSearch cluster not available, skipping IT: " + e.getMessage(), false);
            return;
        }

        // Check hit count without a JSON library: look for "value":N where N > 0.
        assertTrue(
            "Expected hits.total.value > 0 but response was: " + responseBody,
            responseBody.contains("\"value\":") && !responseBody.contains("\"value\":0")
        );
    }

    // -------------------------------------------------------------------------

    private String executeSearch(String index, String body) throws IOException {
        SSLContext sslContext = buildPermissiveSslContext();

        BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(
            new AuthScope(null, -1),
            new UsernamePasswordCredentials(USERNAME, PASSWORD.toCharArray())
        );

        try (CloseableHttpClient client = HttpClients.custom()
                .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                    .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                        .setSslContext(sslContext)
                        .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                        .build())
                    .build())
                .setDefaultCredentialsProvider(credentialsProvider)
                .build()) {

            HttpPost post = new HttpPost(OPENSEARCH_URL + "/" + index + "/_search");
            post.setHeader("Content-Type", "application/json");
            post.setEntity(new StringEntity(body, ContentType.APPLICATION_JSON));

            return client.execute(post, response -> EntityUtils.toString(response.getEntity()));
        }
    }

    private SSLContext buildPermissiveSslContext() {
        try {
            return SSLContextBuilder.create()
                .loadTrustMaterial(null, (chain, authType) -> true)
                .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build permissive SSL context", e);
        }
    }
}
