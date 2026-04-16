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
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.netskope.AbstractNetskopeApiTask;
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
                    baseUrl: "https://{{ secret('NETSKOPE_TENANT') }}.goskope.com"
                    apiToken: "{{ secret('NETSKOPE_V2_TOKEN') }}"
                    policyGroupId: "{{ inputs.policy_group_id }}"
                    operation: ADD
                    entity: "malicious-site.example.com"
                """
        )
    }
)
public class UpdatePolicyGroup extends AbstractNetskopeApiTask implements RunnableTask<UpdatePolicyGroup.Output> {

    @Schema(title = "The ID of the URL list policy group to update")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> policyGroupId;

    @Schema(title = "The operation to perform", description = "Must be 'ADD' or 'REMOVE'")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> operation;

    @Schema(title = "The URL or entity to add or remove from the policy group")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> entity;

    @Override
    public Output run(RunContext runContext) throws Exception {
        String rBaseUrl = runContext.render(this.baseUrl).as(String.class).orElseThrow();
        String rApiToken = runContext.render(this.apiToken).as(String.class).orElseThrow();
        String rPolicyGroupId = runContext.render(this.policyGroupId).as(String.class).orElseThrow();
        String rOperation = runContext.render(this.operation).as(String.class).orElseThrow();
        String rEntity = runContext.render(this.entity).as(String.class).orElseThrow();

        String url = rBaseUrl + "/api/v2/policy/urllist/" + rPolicyGroupId;

        Map<String, Object> requestBody = Map.of(
            "action", rOperation,
            "url", rEntity
        );

        try (var client = new HttpClient(runContext, HttpConfiguration.builder().build())) {
            var httpRequest = HttpRequest.builder()
                .uri(URI.create(url))
                .method("PUT")
                .addHeader("Netskope-Api-Token", rApiToken)
                .addHeader("Content-Type", "application/json")
                .body(HttpRequest.JsonRequestBody.builder().content(requestBody).build())
                .build();
            HttpResponse<String> response = client.request(httpRequest, String.class);
            if (response.getStatus().getCode() >= 400) {
                throw new IOException("Netskope API error " + response.getStatus().getCode() + ": " + response.getBody());
            }

            return Output.builder()
                .policyGroupId(rPolicyGroupId)
                .operation(rOperation)
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
