package io.kestra.plugin.netskope;

import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.Task;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractNetskopeScimTask extends Task {

    @Schema(title = "The base URL of the Netskope tenant", description = "e.g. https://tenant.goskope.com")
    @NotNull
    @PluginProperty(group = "main")
    protected Property<String> baseUrl;

    @Schema(title = "The SCIM Bearer token for authentication")
    @NotNull
    @PluginProperty(group = "main")
    protected Property<String> scimToken;
}
