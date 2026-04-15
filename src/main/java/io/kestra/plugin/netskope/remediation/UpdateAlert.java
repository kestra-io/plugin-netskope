package io.kestra.plugin.netskope.remediation;

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
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Update the status of a Netskope alert",
    description = "Patches an alert in Netskope Security Cloud to set its status and optional note."
)
@Plugin(
    examples = {
        @Example(
            full = true,
            code = """
                id: update_netskope_alert
                namespace: io.kestra.security
                tasks:
                  - id: ack_alert
                    type: io.kestra.plugin.netskope.remediation.UpdateAlert
                    baseUrl: "https://{{ secret('NETSKOPE_TENANT') }}.goskope.com"
                    apiToken: "{{ secret('NETSKOPE_V2_TOKEN') }}"
                    alertId: "{{ inputs.alert_id }}"
                    status: acknowledged
                    note: "Reviewed and acknowledged by SOC team"
                """
        )
    }
)
public class UpdateAlert extends Task implements RunnableTask<UpdateAlert.Output> {

    @Schema(title = "The base URL of the Netskope tenant", description = "e.g. https://tenant.goskope.com")
    @NotNull
    @PluginProperty(group = "connection")
    private Property<String> baseUrl;

    @Schema(title = "The Netskope v2 API token")
    @NotNull
    @PluginProperty(group = "connection")
    private Property<String> apiToken;

    @Schema(title = "The ID of the alert to update")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> alertId;

    @Schema(title = "The new status for the alert", description = "Must be 'acknowledged' or 'dismissed'")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> status;

    @Schema(title = "Optional note to attach to the alert update")
    @PluginProperty(group = "advanced")
    private Property<String> note;

    @Override
    public Output run(RunContext runContext) throws Exception {
        String rBaseUrl = runContext.render(this.baseUrl).as(String.class).orElseThrow();
        String rApiToken = runContext.render(this.apiToken).as(String.class).orElseThrow();
        String rAlertId = runContext.render(this.alertId).as(String.class).orElseThrow();
        String rStatus = runContext.render(this.status).as(String.class).orElseThrow();

        String url = rBaseUrl + "/api/v2/events/alerts/" + rAlertId;

        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("status", rStatus);
        if (this.note != null) {
            String rNote = runContext.render(this.note).as(String.class).orElse(null);
            if (rNote != null) {
                requestBody.put("note", rNote);
            }
        }

        try (var client = new HttpClient(runContext, HttpConfiguration.builder().build())) {
            var httpRequest = HttpRequest.builder()
                .uri(URI.create(url))
                .method("PATCH")
                .addHeader("Netskope-Api-Token", rApiToken)
                .addHeader("Content-Type", "application/json")
                .body(HttpRequest.JsonRequestBody.builder().content(requestBody).build())
                .build();
            HttpResponse<String> response = client.request(httpRequest, String.class);
            if (response.getStatus().getCode() >= 400) {
                throw new IOException("Netskope API error " + response.getStatus().getCode() + ": " + response.getBody());
            }

            return Output.builder()
                .alertId(rAlertId)
                .updatedStatus(rStatus)
                .build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The ID of the updated alert")
        private final String alertId;

        @Schema(title = "The new status that was set on the alert")
        private final String updatedStatus;
    }
}
