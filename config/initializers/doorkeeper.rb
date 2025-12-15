# frozen_string_literal: true

Doorkeeper.configure do
  # Change the ORM that doorkeeper will use (requires ORM extensions installed).
  orm :active_record

  # This block will be called to check whether the resource owner is authenticated or not.
  resource_owner_authenticator do
    current_user || redirect_to(login_path)
  end

  # Restrict access to the admin web interface
  admin_authenticator do
    current_user&.admin? || redirect_to(login_path)
  end

  # Issue access tokens with refresh token
  use_refresh_token

  # Provide support for an owner to be assigned to each registered application
  enable_application_owner confirmation: false

  # Define access token scopes for your provider
  default_scopes :read
  optional_scopes :write, :admin

  # Forbids creating/updating applications with arbitrary scopes
  enforce_configured_scopes

  # Change the way access token is authenticated from the request object
  access_token_methods :from_bearer_authorization, :from_access_token_param

  # Forces the usage of the HTTPS protocol in non-native redirect uris
  force_ssl_in_redirect_uri !Rails.env.development?

  # WWW-Authenticate Realm
  realm "PhishDirectory"

  # Token expiration
  access_token_expires_in 2.hours

  # Authorization code expiration
  authorization_code_expires_in 10.minutes

  # Reuse access token for the same resource owner within an application
  reuse_access_token

  # Grant flows available
  grant_flows %w[authorization_code client_credentials]
end
