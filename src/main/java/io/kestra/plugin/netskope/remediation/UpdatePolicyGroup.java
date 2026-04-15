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
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Update a Netskope URL policy group",
    description = "Adds or removes a URL/entity from a Netskope URL list policy group via the REST API v2."
)
@Plugin(
    examples = {
        @Example(
            full = true,
            code = """
                id: update_netskope_policy
                namespace: io.kestra.security
                tasks:
                  - id: block_url
                    type: io.kestra.plugin.netskope.remediation.UpdatePolicyGroup
                    rBaseUrl: "https://{{ secret('NETSKOPE_TENANT') }}.goskope.com"
                    rApiToken: "{{ secret('NETSKOPE_V2_TOKEN') }}"
                    rPolicyGroupId: "{{ inputs.policy_group_id }}"
                    rOperation: ADD
                    rEntity: "malicious-site.example.com"
                """
        )
    }
)
public class UpdatePolicyGroup extends Task implements RunnableTask<UpdatePolicyGroup.Output> {

    @Schema(title = "The base URL of the Netskope tenant", description = "e.g. https://tenant.goskope.com")
    @NotNull
    @PluginProperty(group = "connection")
    private Property<String> rBaseUrl;

    @Schema(title = "The Netskope v2 API token")
    @NotNull
    @PluginProperty(group = "connection")
    private Property<String> rApiToken;

    @Schema(title = "The ID of the URL list policy group to update")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> rPolicyGroupId;

    @Schema(title = "The operation to perform", description = "Must be 'ADD' or 'REMOVE'")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> rOperation;

    @Schema(title = "The URL or entity to add or remove from the policy group")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> rEntity;

    @Override
    public Output run(RunContext runContext) throws Exception {
        String baseUrlVal = runContext.render(this.rBaseUrl).as(String.class).orElseThrow();
        String apiTokenVal = runContext.render(this.rApiToken).as(String.class).orElseThrow();
        String policyGroupIdVal = runContext.render(this.rPolicyGroupId).as(String.class).orElseThrow();
        String operationVal = runContext.render(this.rOperation).as(String.class).orElseThrow();
        String entityVal = runContext.render(this.rEntity).as(String.class).orElseThrow();

        String url = baseUrlVal + "/api/v2/policy/urllist/" + policyGroupIdVal;

        Map<String, Object> requestBody = Map.of(
            "action", operationVal,
            "url", entityVal
        );

        try (var client = new HttpClient(runContext, HttpConfiguration.builder().build())) {
            var httpRequest = HttpRequest.builder()
                .uri(URI.create(url))
                .method("PUT")
                .addHeader("Netskope-Api-Token", apiTokenVal)
                .addHeader("Content-Type", "application/json")
                .body(HttpRequest.JsonRequestBody.builder().content(requestBody).build())
                .build();
            HttpResponse<String> response = client.request(httpRequest, String.class);
            if (response.getStatus().getCode() >= 400) {
                throw new IOException("Netskope API error " + response.getStatus().getCode() + ": " + response.getBody());
            }

            return Output.builder()
                .policyGroupId(policyGroupIdVal)
                .operation(operationVal)
                .build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The ID of the updated policy group")
        private final String policyGroupId;

        @Schema(title = "The operation that was performed (ADD or REMOVE)")
        private final String operation;
    }
}
