package io.kestra.plugin.netskope.events;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.notNullValue;

@KestraTest
class GetAlertsTest {

    @Inject
    RunContextFactory runContextFactory;

    @EnabledIfEnvironmentVariable(named = "NETSKOPE_API_TOKEN", matches = ".+")
    @Test
    void run() throws Exception {
        var task = GetAlerts.builder()
            .baseUrl(Property.ofExpression("{{ envs.NETSKOPE_BASE_URL }}"))
            .apiToken(Property.ofExpression("{{ envs.NETSKOPE_API_TOKEN }}"))
            .alertType(Property.ofValue("malware"))
            .build();
        var ctx = runContextFactory.of(Map.of());
        var output = task.run(ctx);
        assertThat(output, notNullValue());
        assertThat(output.getAlertCount(), greaterThanOrEqualTo(0));
    }
}
