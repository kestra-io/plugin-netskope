package io.kestra.plugin.netskope.scim;

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
    title = "Manage a user in Netskope via SCIM 2.0",
    description = "Activates or deactivates a user in Netskope Security Cloud using a SCIM 2.0 PATCH operation."
)
@Plugin(
    examples = {
        @Example(
            full = true,
            code = """
                id: disable_netskope_user
                namespace: io.kestra.security
                tasks:
                  - id: deactivate_user
                    type: io.kestra.plugin.netskope.scim.ManageUser
                    baseUrl: "https://{{ secret('NETSKOPE_TENANT') }}.goskope.com"
                    scimToken: "{{ secret('NETSKOPE_SCIM_TOKEN') }}"
                    userId: "{{ inputs.user_id }}"
                    active: false
                """
        )
    }
)
public class ManageUser extends Task implements RunnableTask<ManageUser.Output> {

    @Schema(title = "The base URL of the Netskope tenant", description = "e.g. https://tenant.goskope.com")
    @NotNull
    private Property<String> baseUrl;

    @Schema(title = "The SCIM Bearer token for authentication")
    @NotNull
    private Property<String> scimToken;

    @Schema(title = "The SCIM user ID to update")
    @NotNull
    private Property<String> userId;

    @Schema(title = "Whether the user should be active or inactive")
    @NotNull
    private Property<Boolean> active;

    @Override
    public Output run(RunContext runContext) throws Exception {
        String baseUrlVal = runContext.render(this.baseUrl).as(String.class).orElseThrow();
        String scimTokenVal = runContext.render(this.scimToken).as(String.class).orElseThrow();
        String userIdVal = runContext.render(this.userId).as(String.class).orElseThrow();
        boolean activeVal = runContext.render(this.active).as(Boolean.class).orElseThrow();

        String url = baseUrlVal + "/scim/Users/" + userIdVal;

        Map<String, Object> requestBody = Map.of(
            "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
            "Operations", List.of(
                Map.of(
                    "op", "replace",
                    "path", "active",
                    "value", activeVal
                )
            )
        );

        try (var client = new HttpClient(runContext, HttpConfiguration.builder().build())) {
            var httpRequest = HttpRequest.builder()
                .uri(URI.create(url))
                .method("PATCH")
                .addHeader("Authorization", "Bearer " + scimTokenVal)
                .addHeader("Content-Type", "application/json")
                .body(HttpRequest.JsonRequestBody.builder().content(requestBody).build())
                .build();
            HttpResponse<String> response = client.request(httpRequest, String.class);
            if (response.getStatus().getCode() >= 400) {
                throw new IOException("Netskope SCIM API error " + response.getStatus().getCode() + ": " + response.getBody());
            }

            return Output.builder()
                .userId(userIdVal)
                .active(activeVal)
                .build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The ID of the updated user")
        private final String userId;

        @Schema(title = "The active status that was set on the user")
        private final boolean active;
    }
}
