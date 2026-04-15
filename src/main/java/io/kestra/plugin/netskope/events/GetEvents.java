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
import java.util.List;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Fetch events from Netskope Security Cloud",
    description = "Streams events via the Netskope REST API v2 Data Export endpoint and stores the response as a file in Kestra storage."
)
@Plugin(
    examples = {
        @Example(
            full = true,
            code = """
                id: get_netskope_events
                namespace: io.kestra.security
                tasks:
                  - id: fetch_events
                    type: io.kestra.plugin.netskope.events.GetEvents
                    rBaseUrl: "https://{{ secret('NETSKOPE_TENANT') }}.goskope.com"
                    rApiToken: "{{ secret('NETSKOPE_V2_TOKEN') }}"
                    rEventType: application
                """
        )
    }
)
public class GetEvents extends Task implements RunnableTask<GetEvents.Output> {

    @Schema(title = "The base URL of the Netskope tenant", description = "e.g. https://tenant.goskope.com")
    @NotNull
    @PluginProperty(group = "connection")
    private Property<String> rBaseUrl;

    @Schema(title = "The Netskope v2 API token")
    @NotNull
    @PluginProperty(group = "connection")
    private Property<String> rApiToken;

    @Schema(title = "The event type to retrieve", description = "e.g. application, network, page, infrastructure, audit, etc.")
    @PluginProperty(group = "main")
    private Property<String> rEventType;

    @Schema(title = "Optional NRSQL query filter", description = "Added as the `query` query parameter")
    @PluginProperty(group = "processing")
    private Property<String> rQuery;

    @Override
    public Output run(RunContext runContext) throws Exception {
        String baseUrlVal = runContext.render(this.rBaseUrl).as(String.class).orElseThrow();
        String apiTokenVal = runContext.render(this.rApiToken).as(String.class).orElseThrow();
        String eventTypeVal = this.rEventType != null
            ? runContext.render(this.rEventType).as(String.class).orElse("application")
            : "application";

        StringBuilder urlBuilder = new StringBuilder(baseUrlVal)
            .append("/api/v2/events/dataexport/events/")
            .append(eventTypeVal);

        if (this.rQuery != null) {
            String queryVal = runContext.render(this.rQuery).as(String.class).orElse(null);
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
            int eventCount = ((List<?>) parsed.getOrDefault("data", List.of())).size();

            File tmpFile = File.createTempFile("netskope-events-", ".json");
            Files.writeString(tmpFile.toPath(), body);
            URI storageUri = runContext.storage().putFile(tmpFile);

            return Output.builder()
                .uri(storageUri)
                .eventCount(eventCount)
                .build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "URI of the stored events response JSON file")
        private final URI uri;

        @Schema(title = "Number of events in the response data array")
        private final int eventCount;
    }
}
