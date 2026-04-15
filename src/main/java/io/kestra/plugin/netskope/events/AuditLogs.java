package io.kestra.plugin.netskope.events;

import com.fasterxml.jackson.core.type.TypeReference;
import io.kestra.core.http.HttpRequest;
import io.kestra.core.http.HttpResponse;
import io.kestra.core.http.client.HttpClient;
import io.kestra.core.http.client.configurations.HttpConfiguration;
import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.models.tasks.Task;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Fetch audit logs from Netskope Security Cloud",
    description = "Fetches the audit trail via the Netskope REST API v2 Data Export endpoint and stores the response as a file in Kestra storage."
)
@Plugin(
    examples = {
        @Example(
            full = true,
            code = """
                id: get_netskope_audit_logs
                namespace: io.kestra.security
                tasks:
                  - id: fetch_audit_logs
                    type: io.kestra.plugin.netskope.events.AuditLogs
                    baseUrl: "https://{{ secret('NETSKOPE_TENANT') }}.goskope.com"
                    apiToken: "{{ secret('NETSKOPE_V2_TOKEN') }}"
                    lookbackPeriod: "PT24H"
                """
        )
    }
)
public class AuditLogs extends Task implements RunnableTask<AuditLogs.Output> {

    @Schema(title = "The base URL of the Netskope tenant", description = "e.g. https://tenant.goskope.com")
    @NotNull
    @PluginProperty(group = "connection")
    private Property<String> baseUrl;

    @Schema(title = "The Netskope v2 API token")
    @NotNull
    @PluginProperty(group = "connection")
    private Property<String> apiToken;

    @Schema(title = "Lookback period for audit logs", description = "When set, appends ?starttime=<epoch> computed as Instant.now().minus(lookbackPeriod). ISO-8601 duration e.g. PT24H")
    @PluginProperty(group = "processing")
    private Property<Duration> lookbackPeriod;

    @Override
    public Output run(RunContext runContext) throws Exception {
        String rBaseUrl = runContext.render(this.baseUrl).as(String.class).orElseThrow();
        String rApiToken = runContext.render(this.apiToken).as(String.class).orElseThrow();

        StringBuilder urlBuilder = new StringBuilder(rBaseUrl)
            .append("/api/v2/events/dataexport/events/audit");

        if (this.lookbackPeriod != null) {
            Duration rLookbackPeriod = runContext.render(this.lookbackPeriod).as(Duration.class).orElse(null);
            if (rLookbackPeriod != null) {
                long startEpoch = Instant.now().minus(rLookbackPeriod).getEpochSecond();
                urlBuilder.append("?starttime=").append(startEpoch);
            }
        }

        String url = urlBuilder.toString();

        try (var client = new HttpClient(runContext, HttpConfiguration.builder().build())) {
            var httpRequest = HttpRequest.builder()
                .uri(URI.create(url))
                .method("GET")
                .addHeader("Netskope-Api-Token", rApiToken)
                .build();
            HttpResponse<String> response = client.request(httpRequest, String.class);
            if (response.getStatus().getCode() >= 400) {
                throw new IOException("Netskope API error " + response.getStatus().getCode() + ": " + response.getBody());
            }

            String body = response.getBody();

            Map<String, Object> parsed = JacksonMapper.ofJson().readValue(body, new TypeReference<Map<String, Object>>() {});
            int logCount = ((List<?>) parsed.getOrDefault("data", List.of())).size();

            File tmpFile = File.createTempFile("netskope-audit-", ".json");
            Files.writeString(tmpFile.toPath(), body);
            URI storageUri = runContext.storage().putFile(tmpFile);

            return Output.builder()
                .uri(storageUri)
                .logCount(logCount)
                .build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "URI of the stored audit log response JSON file")
        private final URI uri;

        @Schema(title = "Number of log entries in the response data array")
        private final int logCount;
    }
}
