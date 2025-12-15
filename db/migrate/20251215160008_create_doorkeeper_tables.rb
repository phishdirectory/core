class CreateDoorkeeperTables < ActiveRecord::Migration[8.1]
  def change
    # OAuth Applications
    create_table :oauth_applications, id: :uuid do |t|
      t.string :name, null: false
      t.string :uid, null: false
      t.string :secret, null: false
      t.text :redirect_uri, null: false
      t.string :scopes, default: "", null: false
      t.boolean :confidential, default: true, null: false

      t.timestamps
    end

    add_index :oauth_applications, :uid, unique: true

    # OAuth Access Grants
    create_table :oauth_access_grants, id: :uuid do |t|
      t.uuid :resource_owner_id, null: false
      t.uuid :application_id, null: false
      t.string :token, null: false
      t.integer :expires_in, null: false
      t.text :redirect_uri, null: false
      t.string :scopes, default: "", null: false
      t.datetime :revoked_at

      t.timestamps null: false
    end

    add_index :oauth_access_grants, :token, unique: true
    add_index :oauth_access_grants, :resource_owner_id
    add_index :oauth_access_grants, :application_id

    add_foreign_key :oauth_access_grants, :users, column: :resource_owner_id
    add_foreign_key :oauth_access_grants, :oauth_applications, column: :application_id

    # OAuth Access Tokens
    create_table :oauth_access_tokens, id: :uuid do |t|
      t.uuid :resource_owner_id
      t.uuid :application_id, null: false
      t.string :token, null: false
      t.string :refresh_token
      t.integer :expires_in
      t.string :scopes
      t.datetime :revoked_at
      t.string :previous_refresh_token, default: "", null: false

      t.timestamps null: false
    end

    add_index :oauth_access_tokens, :token, unique: true
    add_index :oauth_access_tokens, :refresh_token, unique: true
    add_index :oauth_access_tokens, :resource_owner_id
    add_index :oauth_access_tokens, :application_id

    add_foreign_key :oauth_access_tokens, :users, column: :resource_owner_id
    add_foreign_key :oauth_access_tokens, :oauth_applications, column: :application_id
  end
end
