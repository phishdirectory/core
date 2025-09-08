# db/migrate/20250614170132_create_doorkeeper_tables.rb
# frozen_string_literal: true

class CreateDoorkeeperTables < ActiveRecord::Migration[8.0]
  def change
    create_table :oauth_applications, id: :uuid do |t|
      t.string  :name,    null: false
      t.string  :uid,     null: false
      t.string  :secret,  null: false
      t.text    :redirect_uri, null: false
      t.string  :scopes,       null: false, default: ''
      t.boolean :confidential, null: false, default: true
      t.timestamps             null: false
    end

    add_index :oauth_applications, :uid, unique: true

    create_table :oauth_access_grants, id: :uuid do |t|
      t.references :resource_owner, null: false, type: :uuid
      t.references :application, null: false, type: :uuid
      t.string   :token,             null: false
      t.integer  :expires_in,        null: false
      t.text     :redirect_uri,      null: false
      t.string   :scopes,            null: false, default: ''
      t.datetime :created_at,        null: false
      t.datetime :revoked_at
    end

    add_index :oauth_access_grants, :token, unique: true
    add_foreign_key(
      :oauth_access_grants,
      :oauth_applications,
      column: :application_id,
      type: :uuid,
      validate: false
    )

    create_table :oauth_access_tokens, id: :uuid do |t|
      t.references :resource_owner, index: true, type: :uuid
      t.references :application, null: false, type: :uuid
      t.string :token, null: false
      t.string   :refresh_token
      t.integer  :expires_in
      t.string   :scopes
      t.datetime :created_at, null: false
      t.datetime :revoked_at
      t.string   :previous_refresh_token, null: false, default: ""
    end

    add_index :oauth_access_tokens, :token, unique: true

    if ActiveRecord::Base.connection.adapter_name == "SQLServer"
      execute <<~SQL.squish
        CREATE UNIQUE NONCLUSTERED INDEX index_oauth_access_tokens_on_refresh_token ON oauth_access_tokens(refresh_token)
        WHERE refresh_token IS NOT NULL
      SQL
    else
      add_index :oauth_access_tokens, :refresh_token, unique: true
    end

    add_foreign_key(
      :oauth_access_tokens,
      :oauth_applications,
      column: :application_id,
      type: :uuid,
      validate: false
    )

    add_foreign_key :oauth_access_grants, :users, column: :resource_owner_id, validate: false, type: :uuid
    add_foreign_key :oauth_access_tokens, :users, column: :resource_owner_id, validate: false, type: :uuid
  end
end
