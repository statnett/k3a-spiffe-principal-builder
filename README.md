# k3a-spiffe-principal-builder

A `KafkaPrincipalBuilder` that will extract a [SPIFFE](https://spiffe.io/) ID
from the Subject Alternative Names (SAN) of an X.509 certificate. Looks for
SANs of type `URI` starting with `spiffe://`, and returns the first one found.
If no match is found, falls back to traditional certificate parsing.

## Usage

The `.jar`-file of this project must be made available on the Kafka
Broker classpath, typically in `/usr/share/java/kafka/`.

Then the broker must be instructed to use this class to build principals by
adding the following to the configuration file:

```properties
<<<<<<< Updated upstream
principal.builder.class=io.statnett.k3a-spiffe.SpiffePrincipalBuilder
=======
principal.builder.class=io.statnett.k3a.authz.spiffe.SpiffePrincipalBuilder
>>>>>>> Stashed changes
```

## References

There is [a KIP-880 requesting this kind of
functionality](https://cwiki.apache.org/confluence/display/KAFKA/KIP-880%3A+X509+SAN+based+SPIFFE+URI+ACL+within+mTLS+Client+Certificates).
