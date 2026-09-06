# frozen_string_literal: true

module Saml
  class IdpController < ApplicationController
    include SamlIdp::Controller

    skip_before_action :verify_authenticity_token, only: [ :create, :logout ]
    before_action :require_saml_enabled
    before_action :validate_saml_request, only: [ :new, :create ]
    before_action :find_service_provider, only: [ :new, :create ]

    # GET /saml/metadata
    # Returns IdP metadata XML for service providers to configure
    def metadata
      render xml: SamlIdp.metadata.signed, content_type: "application/samlmetadata+xml"
    end

    # GET /saml/auth
    # Handle incoming SAML AuthnRequest - show login or redirect to assertion
    def new
      if user_signed_in? && current_user.can_authenticate?
        # User is authenticated, generate assertion
        @saml_response = encode_response(current_user)
        render :create
      else
        # Store SAML request for after authentication
        store_saml_request
        redirect_to login_path, notice: "Please sign in to continue to #{@service_provider&.name || 'the application'}."
      end
    end

    # POST /saml/auth
    # Generate SAML assertion and POST to service provider ACS URL
    def create
      unless user_signed_in? && current_user.can_authenticate?
        redirect_to login_path, alert: "Please sign in to continue."
        return
      end

      @saml_response = encode_response(current_user)

      log_authentication(status: "success")

      render :create
    end

    # POST /saml/logout
    # Handle Single Logout request
    def logout
      # Parse and validate logout request
      logout_request = saml_logout_request

      if logout_request.nil?
        render plain: "Invalid logout request", status: :bad_request
        return
      end

      # Find the user session and invalidate it
      sign_out if user_signed_in?

      # Generate logout response
      logout_response = encode_logout_response(logout_request.id)

      render xml: logout_response
    end

    private

    def require_saml_enabled
      return if Flipper.enabled?(:saml_idp_enabled)

      render plain: "SAML IdP is not enabled", status: :service_unavailable
    end

    def validate_saml_request
      return if saml_request.present? || session[:saml_request_params].present?

      render plain: "Missing SAML request", status: :bad_request
    end

    def find_service_provider
      # Get entity ID from request
      entity_id = saml_request&.issuer || session.dig(:saml_request_params, :issuer)

      @service_provider = Saml::ServiceProvider.enabled.find_by(entity_id: entity_id)

      return if @service_provider&.usable?

      log_authentication(status: "failure", error_message: "Unknown or disabled service provider: #{entity_id}")
      render plain: "Unknown or disabled service provider", status: :forbidden
    end

    def store_saml_request
      # Store request parameters for after authentication
      session[:saml_request_params] = {
        SAMLRequest: params[:SAMLRequest],
        RelayState: params[:RelayState],
        issuer: saml_request&.issuer
      }
      session[:saml_return_to] = saml_auth_path
    end

    def encode_response(user)
      # Override saml_idp's encode_response to use our service provider config
      encode_saml_response(
        user,
        audience_uri: @service_provider.entity_id,
        acs_url: @service_provider.assertion_consumer_service_url,
        name_id: @service_provider.name_id_for(user),
        name_id_format: @service_provider.name_id_format,
        signed_assertion: @service_provider.sign_assertions?,
        signed_message: @service_provider.sign_assertions?,
        encryption: @service_provider.encrypt_assertions? ? {
          cert: OpenSSL::X509::Certificate.new(@service_provider.certificate),
          block_encryption: "aes256-cbc",
          key_transport: "rsa-oaep-mgf1p"
        } : nil,
        attributes: @service_provider.attributes_for(user)
      )
    end

    def encode_saml_response(user, options = {})
      # Build SAML response using saml_idp
      response = SamlIdp::SamlResponse.new(
        reference_id: SecureRandom.uuid,
        response_id: SecureRandom.uuid,
        issuer_uri: SamlIdp.config.base_saml_location,
        principal: user,
        audience_uri: options[:audience_uri],
        saml_request_id: saml_request&.request_id,
        saml_acs_url: options[:acs_url],
        algorithm: :sha256,
        authn_context_classref: @service_provider.authn_context_class_ref ||
          "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        expiry: 3600,
        encryption: options[:encryption],
        session_expiry: 1.hour.from_now,
        name_id_format: options[:name_id_format]
      )

      # Add custom attributes
      if options[:attributes].present?
        options[:attributes].each do |name, value|
          response.add_attribute(name, value) if value.present?
        end
      end

      response.build
    end

    def log_authentication(status:, error_message: nil)
      return unless @service_provider

      @service_provider.log_authentication(
        user: current_user,
        session_index: SecureRandom.uuid,
        status: status,
        ip_address: request.remote_ip,
        user_agent: request.user_agent,
        error_message: error_message
      )
    end

    # Helper to get the SAML auth path
    def saml_auth_path
      saml_auth_url(
        SAMLRequest: session.dig(:saml_request_params, :SAMLRequest),
        RelayState: session.dig(:saml_request_params, :RelayState)
      )
    end

    def saml_logout_request
      return nil unless params[:SAMLRequest]

      SamlIdp::LogoutRequestBuilder.new(
        params[:SAMLRequest],
        SamlIdp.config
      )
    rescue StandardError
      nil
    end

    def encode_logout_response(request_id)
      SamlIdp::LogoutResponseBuilder.new(
        SecureRandom.uuid,
        SamlIdp.config.base_saml_location,
        request_id,
        algorithm: :sha256
      ).signed
    end
  end
end
