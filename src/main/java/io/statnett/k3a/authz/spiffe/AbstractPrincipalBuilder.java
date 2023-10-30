package io.statnett.k3a.authz.spiffe;

import org.apache.kafka.common.Configurable;
import org.apache.kafka.common.config.internals.BrokerSecurityConfigs;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalBuilder;
import org.apache.kafka.common.security.auth.KafkaPrincipalSerde;
import org.apache.kafka.common.security.authenticator.DefaultKafkaPrincipalBuilder;
import org.apache.kafka.common.security.kerberos.KerberosShortNamer;
import org.apache.kafka.common.security.ssl.SslPrincipalMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.kerberos.KerberosPrincipal;
import java.util.List;
import java.util.Map;

public abstract class AbstractPrincipalBuilder
implements KafkaPrincipalBuilder, KafkaPrincipalSerde, Configurable {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractPrincipalBuilder.class);
    private DefaultKafkaPrincipalBuilder defaultKafkaPrincipalBuilder;

    protected final KafkaPrincipal delegateToDefaultBuilder(final AuthenticationContext context) {
        if (defaultKafkaPrincipalBuilder == null) {
            LOG.error("No defaultKafkaPrincipalBuilder, which means this class has not been properly configured. Falling back to ANONYMOUS.");
            return KafkaPrincipal.ANONYMOUS;
        }
        return defaultKafkaPrincipalBuilder.build(context);
    }

    @Override
    public final void configure(final Map<String, ?> configs) {
        defaultKafkaPrincipalBuilder = createDefaultKafkaPrincipalBuilder(configs);
        doConfigure(configs);
    }

    protected void doConfigure(final Map<String, ?> configs) {
        /* Subclasses may implement. */
    }

    @Override
    public final byte[] serialize(final KafkaPrincipal principal)
    throws SerializationException {
        assertDefaultPrincipalBuilderSet();
        return defaultKafkaPrincipalBuilder.serialize(principal);
    }

    @Override
    public final KafkaPrincipal deserialize(final byte[] bytes)
    throws SerializationException {
        assertDefaultPrincipalBuilderSet();
        return defaultKafkaPrincipalBuilder.deserialize(bytes);
    }

    private void assertDefaultPrincipalBuilderSet() {
        if (defaultKafkaPrincipalBuilder == null) {
            throw new IllegalStateException("No defaultKafkaPrincipalBuilder, which means this class has not been properly configured.");
        }
    }

    /**
     * Builds a <code>DefaultKafkaPrincipalBuilder</code> from the configuration. This code duplicates
     * code found in a couple of <code>ChannelBuilder</code>s in Kafka, as there is no other way to
     * fetch the builder.
     *
     * @param configs broker configurations
     * @return a <code>DefaultKafkaPrincipalBuilder</code> configured according to the config.
     */
    private DefaultKafkaPrincipalBuilder createDefaultKafkaPrincipalBuilder(final Map<String, ?> configs) {
        /* SslPrincipalMapper init from org.apache.kafka.common.network.SslChannelBuilder */
        final String sslPrincipalMappingRules = (String) configs.get(BrokerSecurityConfigs.SSL_PRINCIPAL_MAPPING_RULES_CONFIG);
        final SslPrincipalMapper sslPrincipalMapper = SslPrincipalMapper.fromRules(sslPrincipalMappingRules);

        /* KerberosShortNamer init from org.apache.kafka.common.network.SaslChannelBuilder */
        String defaultRealm;
        try {
            // see https://issues.apache.org/jira/browse/HADOOP-10848 for details
            defaultRealm = new KerberosPrincipal("tmp", 1).getRealm();
        } catch (final Exception e) {
            defaultRealm = "";
        }
        final List<String> principalToLocalRules = (List<String>) configs.get(BrokerSecurityConfigs.SASL_KERBEROS_PRINCIPAL_TO_LOCAL_RULES_CONFIG);
        final KerberosShortNamer kerberosShortNamer = KerberosShortNamer.fromUnparsedRules(defaultRealm, principalToLocalRules);

        return new DefaultKafkaPrincipalBuilder(kerberosShortNamer, sslPrincipalMapper);
    }

}
