# frozen_string_literal: true

module Saml
  class IdpController < ApplicationController
    include SamlIdp::Controller

    # Fallback when a service provider does not name its own context class.
    DEFAULT_AUTHN_CONTEXT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    # The parameters that make up a redirect-binding request. All of them have
    # to survive the trip through the login page, because the signature covers
    # SAMLRequest, RelayState and SigAlg together.
    SAML_REQUEST_PARAMS = %w[SAMLRequest RelayState SigAlg Signature].freeze

    ASSERTION_LIFETIME = 1.hour

    helper_method :saml_relay_state

    skip_before_action :verify_authenticity_token, only: [ :create, :logout ]
    before_action :require_saml_enabled
    before_action :decode_saml_request, only: [ :new, :create ]
    before_action :find_service_provider, only: [ :new, :create ]
    before_action :validate_saml_request, only: [ :new, :create ]

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
        log_authentication(status: "success")
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

      render xml: encode_logout_response(logout_request)
    end

    private

    def require_saml_enabled
      return if Flipper.enabled?(:saml_idp_enabled)

      render plain: "SAML IdP is not enabled", status: :service_unavailable
    end

    # Turns the encoded request into a SamlIdp::Request. Nothing downstream
    # works until this runs: saml_idp's default saml_request is an empty stub
    # whose issuer is nil, so skipping the decode means the service provider
    # can never be found.
    def decode_saml_request
      raw_request = saml_param("SAMLRequest")

      if raw_request.blank?
        render plain: "Missing SAML request", status: :bad_request
        return
      end

      decode_request(
        raw_request,
        saml_param("Signature"),
        saml_param("SigAlg"),
        saml_param("RelayState")
      )

      return if saml_request.authn_request?

      render plain: "Invalid SAML request", status: :bad_request
    rescue StandardError => e
      Rails.logger.warn("SAML: could not decode AuthnRequest: #{e.class}: #{e.message}")
      render plain: "Invalid SAML request", status: :bad_request
    end

    def find_service_provider
      entity_id = saml_request.issuer

      @service_provider = Saml::ServiceProvider.enabled.find_by(entity_id: entity_id)

      return if @service_provider&.usable?

      Rails.logger.warn("SAML: unknown or disabled service provider: #{entity_id.inspect}")
      render plain: "Unknown or disabled service provider", status: :forbidden
    end

    # saml_idp checks the issuer, the request shape, the signature when the
    # provider requires one, and that the destination host is one we accept.
    # The previous version only checked that a request was present, so an
    # unsigned request was never rejected.
    def validate_saml_request
      return if valid_saml_request?

      reasons = saml_request.errors.join(", ")
      log_authentication(status: "failure", error_message: "Rejected SAML request: #{reasons}")
      Rails.logger.warn("SAML: rejected AuthnRequest from #{saml_request.issuer.inspect}: #{reasons}")
      render plain: "Invalid SAML request", status: :forbidden
    end

    # Reads a request parameter, falling back to the copy stored before the
    # login redirect.
    def saml_param(key)
      value = params[key]
      return value if value.present?

      session.dig(:saml_request_params, key)
    end

    # The provider expects its RelayState echoed back. After a login redirect it
    # only exists in the session, so the view cannot read it off params.
    def saml_relay_state
      saml_param("RelayState")
    end

    def store_saml_request
      session[:saml_request_params] = SAML_REQUEST_PARAMS.index_with { |key| params[key] }.compact
      # AuthController reads return_to. The old code wrote saml_return_to, which
      # nothing has ever read, so signing in dropped the user on the dashboard
      # and abandoned the SAML flow.
      session[:return_to] = saml_return_path
    end

    def saml_return_path
      saml_auth_path(session.fetch(:saml_request_params, {}).symbolize_keys)
    end

    def encode_response(user)
      encode_authn_response(
        user,
        issuer_uri: SamlIdp.config.base_saml_location,
        audience_uri: @service_provider.entity_id,
        acs_url: @service_provider.assertion_consumer_service_url,
        algorithm: :sha256,
        authn_context_classref: @service_provider.authn_context_class_ref.presence || DEFAULT_AUTHN_CONTEXT,
        expiry: ASSERTION_LIFETIME.to_i,
        session_expiry: ASSERTION_LIFETIME.to_i,
        name_id_formats: @service_provider.name_id_formats,
        attributes: @service_provider.saml_attributes_for(user),
        signed_message: @service_provider.sign_assertions?,
        signed_assertion: @service_provider.sign_assertions?,
        encryption: encryption_options
      )
    end

    def encryption_options
      return nil unless @service_provider.encrypt_assertions?
      return nil if @service_provider.certificate.blank?

      {
        cert: OpenSSL::X509::Certificate.new(@service_provider.certificate),
        block_encryption: "aes256-cbc",
        key_transport: "rsa-oaep-mgf1p"
      }
    end

    def log_authentication(status:, error_message: nil)
      return unless @service_provider
      return unless current_user

      @service_provider.log_authentication(
        user: current_user,
        session_index: SecureRandom.uuid,
        status: status,
        ip_address: request.remote_ip,
        user_agent: request.user_agent,
        error_message: error_message
      )
    end

    def saml_logout_request
      return nil if params[:SAMLRequest].blank?

      request = SamlIdp::Request.from_deflated_request(
        params[:SAMLRequest],
        saml_request: params[:SAMLRequest],
        signature: params[:Signature],
        sig_algorithm: params[:SigAlg],
        relay_state: params[:RelayState]
      )

      return nil unless request.logout_request?
      return nil unless request.valid?

      request
    rescue StandardError
      nil
    end

    # Destination is the provider's own logout endpoint, which saml_idp reads
    # back off the decoded request through the service provider finder.
    def encode_logout_response(logout_request)
      SamlIdp::LogoutResponseBuilder.new(
        SecureRandom.uuid,
        SamlIdp.config.base_saml_location,
        logout_request.logout_url,
        logout_request.request_id,
        :sha256
      ).signed
    end
  end
end
