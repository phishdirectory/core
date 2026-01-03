# frozen_string_literal: true

# SAML Identity Provider Configuration
#
# This configures Core as a SAML 2.0 Identity Provider (IdP).
# Service Providers (SPs) authenticate users through Core using SAML assertions.
#
# Required credentials:
#   saml:
#     certificate: |
#       -----BEGIN CERTIFICATE-----
#       ...
#       -----END CERTIFICATE-----
#     private_key: |
#       -----BEGIN RSA PRIVATE KEY-----
#       ...
#       -----END RSA PRIVATE KEY-----
#
# To generate a self-signed certificate for development:
#   openssl req -x509 -newkey rsa:4096 -keyout saml_key.pem -out saml_cert.pem -days 3650 -nodes \
#     -subj "/CN=core.phish.directory/O=phish.directory/C=US"

SamlIdp.configure do |config|
  # Base URL for SAML endpoints
  config.base_saml_location = "#{Rails.application.config.x.app_host}/saml"

  # IdP Entity ID
  config.entity_id = "#{Rails.application.config.x.app_host}/saml/metadata"

  # Signing certificate and private key from Rails credentials
  if Rails.application.credentials.dig(:saml, :certificate).present?
    config.x509_certificate = Rails.application.credentials.dig(:saml, :certificate)
    config.secret_key = Rails.application.credentials.dig(:saml, :private_key)
  else
    # Development fallback - generate ephemeral key pair
    # WARNING: This changes on each restart - not suitable for production!
    if Rails.env.development? || Rails.env.test?
      Rails.logger.warn "SAML: Using ephemeral key pair. Configure credentials.saml.certificate and credentials.saml.private_key for production."

      require "openssl"
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = OpenSSL::X509::Name.parse("/CN=core.phish.directory.dev/O=phish.directory/C=US")
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now
      cert.not_after = Time.now + 365 * 24 * 60 * 60 # 1 year
      cert.sign(key, OpenSSL::Digest::SHA256.new)

      config.x509_certificate = cert.to_pem
      config.secret_key = key.to_pem
    end
  end

  # Signature algorithm
  config.algorithm = :sha256

  # Organization info for metadata
  config.organization_name = "phish.directory"
  config.organization_url = "https://phish.directory"

  # Technical contact
  config.technical_contact.company = "phish.directory"
  config.technical_contact.email_address = "security@phish.directory"

  # Attribute service - dynamically look up service provider configs
  config.service_provider.finder = lambda { |issuer_or_entity_id|
    sp = Saml::ServiceProvider.enabled.find_by(entity_id: issuer_or_entity_id)

    if sp&.usable?
      {
        acs_url: sp.assertion_consumer_service_url,
        cert: sp.certificate,
        fingerprint: nil,
        metadata_url: sp.metadata_url,
        response_hosts: [URI.parse(sp.assertion_consumer_service_url).host]
      }
    end
  }

  # Name ID format
  config.name_id.formats = {
    email_address: ->(principal) { principal.email },
    persistent: ->(principal) { principal.pd_id },
    transient: ->(principal) { SecureRandom.uuid }
  }

  # Session expiry (in seconds)
  config.session_expiry = 1.hour.to_i
end
