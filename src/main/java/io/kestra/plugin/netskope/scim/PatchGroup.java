package io.kestra.plugin.netskope.scim;

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
import java.util.List;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Add or remove a member from a Netskope SCIM group",
    description = "Patches a group in Netskope Security Cloud via SCIM 2.0 to add or remove a member by email."
)
@Plugin(
    examples = {
        @Example(
            full = true,
            code = """
                id: patch_netskope_group
                namespace: io.kestra.security
                tasks:
                  - id: add_member
                    type: io.kestra.plugin.netskope.scim.PatchGroup
                    baseUrl: "https://{{ secret('NETSKOPE_TENANT') }}.goskope.com"
                    scimToken: "{{ secret('NETSKOPE_SCIM_TOKEN') }}"
                    groupId: "{{ inputs.group_id }}"
                    operation: ADD
                    memberEmail: "user@example.com"
                """
        )
    }
)
public class PatchGroup extends Task implements RunnableTask<PatchGroup.Output> {

    @Schema(title = "The base URL of the Netskope tenant", description = "e.g. https://tenant.goskope.com")
    @NotNull
    @PluginProperty(group = "connection")
    private Property<String> baseUrl;

    @Schema(title = "The SCIM Bearer token for authentication")
    @NotNull
    @PluginProperty(group = "connection")
    private Property<String> scimToken;

    @Schema(title = "The SCIM group ID to update")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> groupId;

    @Schema(title = "The operation to perform on group membership", description = "Must be 'ADD' or 'REMOVE'")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> operation;

    @Schema(title = "The email address of the member to add or remove")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> memberEmail;

    @Override
    public Output run(RunContext runContext) throws Exception {
        String rBaseUrl = runContext.render(this.baseUrl).as(String.class).orElseThrow();
        String rScimToken = runContext.render(this.scimToken).as(String.class).orElseThrow();
        String rGroupId = runContext.render(this.groupId).as(String.class).orElseThrow();
        String rOperation = runContext.render(this.operation).as(String.class).orElseThrow();
        String rMemberEmail = runContext.render(this.memberEmail).as(String.class).orElseThrow();

        String url = rBaseUrl + "/scim/Groups/" + rGroupId;

        String op = rOperation.equalsIgnoreCase("ADD") ? "add" : "remove";

        Map<String, Object> requestBody = Map.of(
            "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
            "Operations", List.of(
                Map.of(
                    "op", op,
                    "path", "members",
                    "value", List.of(Map.of("display", rMemberEmail))
                )
            )
        );

        try (var client = new HttpClient(runContext, HttpConfiguration.builder().build())) {
            var httpRequest = HttpRequest.builder()
                .uri(URI.create(url))
                .method("PATCH")
                .addHeader("Authorization", "Bearer " + rScimToken)
                .addHeader("Content-Type", "application/json")
                .body(HttpRequest.JsonRequestBody.builder().content(requestBody).build())
                .build();
            HttpResponse<String> response = client.request(httpRequest, String.class);
            if (response.getStatus().getCode() >= 400) {
                throw new IOException("Netskope SCIM API error " + response.getStatus().getCode() + ": " + response.getBody());
            }

            return Output.builder()
                .groupId(rGroupId)
                .operation(rOperation)
                .build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The ID of the updated group")
        private final String groupId;

        @Schema(title = "The operation that was performed (ADD or REMOVE)")
        private final String operation;
    }
}
