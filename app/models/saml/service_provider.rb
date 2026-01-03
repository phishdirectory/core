# frozen_string_literal: true

module Saml
  class ServiceProvider < ApplicationRecord
    include SoftDeletable
    include PublicIdentifiable

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
    validates :entity_id, presence: true, uniqueness: true
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

    # ===========================================
    # Configuration helpers
    # ===========================================

    def usable?
      enabled? && !discarded?
    end

    # Get the name ID for a user based on format
    def name_id_for(user)
      case name_id_format
      when NAME_ID_FORMATS[:email]
        user.email
      when NAME_ID_FORMATS[:persistent]
        user.pd_id
      else
        user.email
      end
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
  end
end
