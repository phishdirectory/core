# frozen_string_literal: true

# Lets an operator require that a service provider signs its AuthnRequests.
# The IdP never verified request signatures before, so this defaults to false
# to keep every existing integration working. Turn it on per provider once that
# provider is known to sign.
class AddWantAuthnRequestsSignedToSamlServiceProviders < ActiveRecord::Migration[8.1]
  def change
    add_column :saml_service_providers, :want_authn_requests_signed, :boolean,
               default: false, null: false
  end
end
