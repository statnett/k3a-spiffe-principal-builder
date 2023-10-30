package io.statnett.k3aspiffe;

import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

public final class SpiffePrincipalBuilder
extends AbstractPrincipalBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(SpiffePrincipalBuilder.class);
    private static final String SPIFFE_PRINCIPAL_TYPE = "SPIFFE";
    private static final String SPIFFE_URI_PREFIX = "spiffe://";

    @Override
    public KafkaPrincipal build(final AuthenticationContext context) {
        if (!(context instanceof SslAuthenticationContext)) {
            return delegateToDefaultBuilder(context);
        }
        final String spiffeId = findSpiffeId((SslAuthenticationContext) context);
        if (spiffeId == null) {
            return delegateToDefaultBuilder(context);
        }
        return new KafkaPrincipal(SPIFFE_PRINCIPAL_TYPE, spiffeId);
    }

    private String findSpiffeId(final SslAuthenticationContext context) {
        final SSLSession session = context.session();
        if (session == null) {
            LOG.error("No session found on " + context.getClass().getSimpleName());
            return null;
        }
        final X509Certificate certificate = findFirstX509Certificate(session);
        if (certificate == null) {
            return null;
        }
        return findSpiffeId(certificate);
    }

    private X509Certificate findFirstX509Certificate(final SSLSession session) {
        try {
            final Certificate[] peerCertificates = session.getPeerCertificates();
            if (peerCertificates.length > 0 && peerCertificates[0] instanceof X509Certificate) {
                return (X509Certificate) peerCertificates[0];
            }
            LOG.error("No X509 certificate found on " + session.getClass().getSimpleName());
            return null;
        } catch (final SSLPeerUnverifiedException e) {
            LOG.warn("Got exception when looking for certificates in session. Pretending there is no SPIFFE ID.", e);
            return null;
        }
    }

    private String findSpiffeId(final X509Certificate certificate) {
        try {
            final Collection<List<?>> subjectAlternativeNames = certificate.getSubjectAlternativeNames();
            if (subjectAlternativeNames == null) {
                return null;
            }
            for (final List<?> typeAndValue : subjectAlternativeNames) {
                if (typeAndValue.size() < 2 || !(typeAndValue.get(1) instanceof String)) {
                    continue;
                }
                final String value = (String) typeAndValue.get(1);
                if (value.startsWith(SPIFFE_URI_PREFIX)) {
                    return value;
                }
            }
            return null;
        } catch (final CertificateParsingException e) {
            LOG.warn("Got exception extracting SPIFFE ID from certificate. Pretending there is no ID.", e);
            return null;
        }
    }

}
