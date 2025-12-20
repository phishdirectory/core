# Disable CRL checking - OpenSSL 3.x enables this by default but CRL endpoints
# can be unreachable. Certificates are still verified for validity.
ENV['OPENSSL_CONF'] = '/dev/null' if ENV['OPENSSL_CONF'].nil?
