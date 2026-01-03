# frozen_string_literal: true

class CreateSamlTables < ActiveRecord::Migration[8.1]
  def change
    # SAML Service Providers (apps that use Core as IdP)
    create_table :saml_service_providers, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      t.references :service, type: :uuid, foreign_key: true
      t.string :name, null: false
      t.string :entity_id, null: false
      t.text :assertion_consumer_service_url, null: false
      t.text :single_logout_service_url
      t.text :metadata_url
      t.text :certificate # SP's certificate for encrypted assertions
      t.string :name_id_format, default: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      t.string :authn_context_class_ref
      t.boolean :sign_assertions, default: true
      t.boolean :encrypt_assertions, default: false
      t.boolean :enabled, default: true
      t.jsonb :attribute_statement, default: {}
      t.datetime :discarded_at

      t.timestamps
    end

    # service_id index already created by t.references
    safety_assured do
      add_index :saml_service_providers, :entity_id, unique: true
      add_index :saml_service_providers, :enabled
      add_index :saml_service_providers, :discarded_at
    end

    # SAML authentication events for auditing
    create_table :saml_authentications, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      t.references :user, type: :uuid, foreign_key: true
      t.references :service_provider, type: :uuid, foreign_key: { to_table: :saml_service_providers }
      t.string :session_index
      t.string :name_id
      t.string :authn_context
      t.string :ip_address
      t.string :user_agent
      t.string :status # success, failure
      t.text :error_message

      t.datetime :created_at, null: false
    end

    # user_id and service_provider_id indexes already created by t.references
    safety_assured do
      add_index :saml_authentications, %i[user_id created_at]
      add_index :saml_authentications, :created_at
      add_index :saml_authentications, :status
    end
  end
end
