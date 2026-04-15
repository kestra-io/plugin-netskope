package io.kestra.plugin.netskope.scim;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

@KestraTest
class PatchGroupTest {

    @Inject
    RunContextFactory runContextFactory;

    @EnabledIfEnvironmentVariable(named = "NETSKOPE_SCIM_TOKEN", matches = ".+")
    @Test
    void run() throws Exception {
        var task = PatchGroup.builder()
            .rBaseUrl(Property.ofExpression("{{ envs.NETSKOPE_BASE_URL }}"))
            .rScimToken(Property.ofExpression("{{ envs.NETSKOPE_SCIM_TOKEN }}"))
            .rGroupId(Property.ofExpression("{{ envs.NETSKOPE_SCIM_GROUP_ID }}"))
            .rOperation(Property.ofValue("ADD"))
            .rMemberEmail(Property.ofValue("test-user@example.com"))
            .build();
        var ctx = runContextFactory.of(Map.of());
        var output = task.run(ctx);
        assertThat(output, notNullValue());
        assertThat(output.getOperation(), is("ADD"));
    }
}
