# frozen_string_literal: true

module Saml
  class ServiceProvider < ApplicationRecord
    include SoftDeletable
    include EncodedIds::UuidIdentifiable

    self.table_name = "saml_service_providers"

    set_public_id_prefix "ssp"

    has_paper_trail

    # Associations
    belongs_to :service, optional: true
    has_many :authentications, class_name: "Saml::Authentication",
             foreign_key: :service_provider_id,
             dependent: :destroy,
             inverse_of: :service_provider

    # Validations
    validates :name, presence: true
    validates :entity_id, presence: true, uniqueness: { conditions: -> { kept } }
    validates :assertion_consumer_service_url, presence: true
    validates :name_id_format, presence: true

    # Scopes
    scope :enabled, -> { where(enabled: true) }

    # Default name ID formats
    NAME_ID_FORMATS = {
      email: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
      transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
      unspecified: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    }.freeze

    # saml_idp builds the NameID Format URN from the SAML version and the key,
    # so the shape has to be { version => { key => getter } }. Giving it the
    # URN string directly does not work. Keeping the version here is what makes
    # emailAddress come out as 1.1 rather than 2.0.
    NAME_ID_BUILDERS = {
      NAME_ID_FORMATS[:email] => [ "1.1", :email_address, ->(user) { user.email } ],
      NAME_ID_FORMATS[:persistent] => [ "2.0", :persistent, ->(user) { user.pd_id } ],
      NAME_ID_FORMATS[:transient] => [ "2.0", :transient, ->(_user) { SecureRandom.uuid } ],
      NAME_ID_FORMATS[:unspecified] => [ "1.1", :unspecified, ->(user) { user.email } ]
    }.freeze

    # ===========================================
    # Configuration helpers
    # ===========================================

    def usable?
      enabled? && !discarded?
    end

    # Get the name ID for a user based on format
    def name_id_for(user)
      _version, _key, getter = name_id_builder
      getter.call(user)
    end

    # The name_id_formats option saml_idp expects for this provider.
    def name_id_formats
      version, key, getter = name_id_builder
      { version => { key => getter } }
    end

    # saml_idp expects { friendly_name => { name:, name_format:, getter: } },
    # not { friendly_name => value }. The values are already computed per user,
    # so each one becomes a getter that ignores the principal and returns it.
    def saml_attributes_for(user)
      attributes_for(user).each_with_object({}) do |(name, value), attrs|
        next if value.blank?

        attrs[name] = { getter: ->(_principal) { value } }
      end
    end

    # SHA256 fingerprint of the provider certificate, which saml_idp needs
    # alongside the certificate itself before it will check a request signature.
    def certificate_fingerprint
      return nil if certificate.blank?

      SamlIdp::Fingerprint.certificate_digest(certificate, :sha256)
    rescue OpenSSL::X509::CertificateError
      nil
    end

    # Build attribute statement for SAML assertion
    def attributes_for(user)
      base_attributes = {
        "email" => user.email,
        "pd_id" => user.pd_id,
        "name" => user.full_name,
        "first_name" => user.first_name,
        "last_name" => user.last_name
      }

      # Add custom attributes from attribute_statement config
      custom_attrs = attribute_statement.transform_values do |attr_source|
        user.public_send(attr_source) if user.respond_to?(attr_source)
      end

      base_attributes.merge(custom_attrs.compact)
    end

    # ===========================================
    # Logging
    # ===========================================

    def log_authentication(user:, session_index:, status:, ip_address: nil, user_agent: nil, error_message: nil)
      authentications.create!(
        user: user,
        session_index: session_index,
        name_id: name_id_for(user),
        authn_context: authn_context_class_ref,
        ip_address: ip_address,
        user_agent: user_agent,
        status: status,
        error_message: error_message
      )
    end

    private

    def name_id_builder
      NAME_ID_BUILDERS.fetch(name_id_format) { NAME_ID_BUILDERS.fetch(NAME_ID_FORMATS[:email]) }
    end
  end
end
