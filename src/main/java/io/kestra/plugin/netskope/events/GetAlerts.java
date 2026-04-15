package io.kestra.plugin.netskope.events;

import com.fasterxml.jackson.core.type.TypeReference;
import io.kestra.core.http.HttpRequest;
import io.kestra.core.http.HttpResponse;
import io.kestra.core.http.client.HttpClient;
import io.kestra.core.http.client.configurations.HttpConfiguration;
import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.models.tasks.Task;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Fetch alerts from Netskope Security Cloud",
    description = "Polls alerts via the Netskope REST API v2 Data Export endpoint and stores the response as a file in Kestra storage."
)
@Plugin(
    examples = {
        @Example(
            full = true,
            code = """
                id: get_netskope_alerts
                namespace: io.kestra.security
                tasks:
                  - id: fetch_alerts
                    type: io.kestra.plugin.netskope.events.GetAlerts
                    baseUrl: "https://{{ secret('NETSKOPE_TENANT') }}.goskope.com"
                    apiToken: "{{ secret('NETSKOPE_V2_TOKEN') }}"
                    alertType: malware
                    query: "alert_severity eq 'critical'"
                """
        )
    }
)
public class GetAlerts extends Task implements RunnableTask<GetAlerts.Output> {

    @Schema(title = "The base URL of the Netskope tenant", description = "e.g. https://tenant.goskope.com")
    @NotNull
    private Property<String> baseUrl;

    @Schema(title = "The Netskope v2 API token")
    @NotNull
    private Property<String> apiToken;

    @Schema(title = "The alert type to retrieve", description = "e.g. malware, dlp, policy, compromised-credentials, etc.")
    private Property<String> alertType;

    @Schema(title = "Optional NRSQL query filter", description = "Added as the `query` query parameter")
    private Property<String> query;

    @Override
    public Output run(RunContext runContext) throws Exception {
        String baseUrlVal = runContext.render(this.baseUrl).as(String.class).orElseThrow();
        String apiTokenVal = runContext.render(this.apiToken).as(String.class).orElseThrow();
        String alertTypeVal = this.alertType != null
            ? runContext.render(this.alertType).as(String.class).orElse("malware")
            : "malware";

        StringBuilder urlBuilder = new StringBuilder(baseUrlVal)
            .append("/api/v2/events/dataexport/alerts/")
            .append(alertTypeVal);

        if (this.query != null) {
            String queryVal = runContext.render(this.query).as(String.class).orElse(null);
            if (queryVal != null && !queryVal.isBlank()) {
                urlBuilder.append("?query=").append(java.net.URLEncoder.encode(queryVal, java.nio.charset.StandardCharsets.UTF_8));
            }
        }

        String url = urlBuilder.toString();

        try (var client = new HttpClient(runContext, HttpConfiguration.builder().build())) {
            var httpRequest = HttpRequest.builder()
                .uri(URI.create(url))
                .method("GET")
                .addHeader("Netskope-Api-Token", apiTokenVal)
                .build();
            HttpResponse<String> response = client.request(httpRequest, String.class);
            if (response.getStatus().getCode() >= 400) {
                throw new IOException("Netskope API error " + response.getStatus().getCode() + ": " + response.getBody());
            }

            String body = response.getBody();

            Map<String, Object> parsed = JacksonMapper.ofJson().readValue(body, new TypeReference<Map<String, Object>>() {});
            int alertCount = ((List<?>) parsed.getOrDefault("data", List.of())).size();

            File tmpFile = File.createTempFile("netskope-alerts-", ".json");
            Files.writeString(tmpFile.toPath(), body);
            URI storageUri = runContext.storage().putFile(tmpFile);

            return Output.builder()
                .uri(storageUri)
                .alertCount(alertCount)
                .build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "URI of the stored alert response JSON file")
        private final URI uri;

        @Schema(title = "Number of alerts in the response data array")
        private final int alertCount;
    }
}
