package no.statnett.k3aspiffe;

import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.SaslAuthenticationContext;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSession;
import javax.security.sasl.SaslServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class SpiffePrincipalBuilderTest {

    private static final InetAddress LOCALHOST;

    static {
        try {
            LOCALHOST = InetAddress.getLocalHost();
        } catch (final UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    private AuthenticationContext createSslContext(final String certPath) {
        try (final InputStream in = getClass().getClassLoader().getResourceAsStream(certPath)) {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            final X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(in);
            final SSLSession sslSession = mock(SSLSession.class);
            when(sslSession.getPeerCertificates()).thenReturn(new Certificate[]{ cert });
            when(sslSession.getPeerPrincipal()).thenReturn(cert.getSubjectX500Principal());
            return new SslAuthenticationContext(sslSession, LOCALHOST, SecurityProtocol.SSL.name());
        } catch (final CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void shouldFallBackToAnonymousForMissingConfig() {
        final KafkaPrincipal principal = new SpiffePrincipalBuilder().build(createSslContext("cn-cert.crt"));
        assertNotNull(principal);
        assertEquals(KafkaPrincipal.ANONYMOUS.getName(), principal.getName());
    }

    @Test
    public void shouldExtractFromCnCertificate() {
        final KafkaPrincipal principal = createBuilder().build(createSslContext("cn-cert.crt"));
        assertNotNull(principal);
        assertEquals(KafkaPrincipal.USER_TYPE, principal.getPrincipalType());
        assertEquals("CN=cn-cert", principal.getName());
    }

    @Test
    public void shouldExtractFromSpiffeCertificate() {
        final KafkaPrincipal principal = createBuilder().build(createSslContext("spiffe-cert.crt"));
        assertNotNull(principal);
        assertEquals("SPIFFE", principal.getPrincipalType());
        assertEquals("spiffe://foo/ns/bar/sa/gazonk", principal.getName());
    }

    @Test
    public void shouldExtractFromSaslUser() {
        final String userId = "foo@example.com";
        final SaslServer saslServer = mock(SaslServer.class);
        when(saslServer.getAuthorizationID()).thenReturn(userId);
        when(saslServer.getMechanismName()).thenReturn("PLAIN");
        final SaslAuthenticationContext context = new SaslAuthenticationContext(saslServer, SecurityProtocol.SASL_SSL, LOCALHOST, "SASL_SSL");
        final KafkaPrincipal principal = createBuilder().build(context);
        assertNotNull(principal);
        assertEquals(KafkaPrincipal.USER_TYPE, principal.getPrincipalType());
        assertEquals(userId, principal.getName());
    }

    private SpiffePrincipalBuilder createBuilder() {
        final SpiffePrincipalBuilder builder = new SpiffePrincipalBuilder();
        builder.configure(Collections.emptyMap());
        return builder;
    }

}
