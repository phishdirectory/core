# frozen_string_literal: true

class CreateUsers < ActiveRecord::Migration[8.1]
  def change
    # Users table
    create_table :users, id: :uuid do |t|
      # Identity
      t.string :first_name, null: false
      t.string :last_name, null: false
      t.string :pd_id, null: false
      t.string :username, null: false

      # Email
      t.string :email, null: false
      t.boolean :email_verified, default: false
      t.datetime :email_verified_at

      # Magic Link Authentication (passwordless)
      t.string :magic_link_token
      t.datetime :magic_link_token_sent_at
      t.datetime :magic_link_expires_at
      t.datetime :magic_link_used_at

      # Access control
      t.column :access_level, :access_level, default: "user", null: false
      t.column :status, :status, default: "active", null: false
      t.boolean :staff, default: false, null: false
      t.boolean :pd_dev, default: false, null: false
      t.boolean :pretend_is_not_admin, default: false, null: false

      # Session settings
      t.integer :session_duration_seconds, default: 2592000, null: false # 30 days

      # Account status
      t.datetime :locked_at

      # Activity tracking
      t.datetime :last_api_activity_at

      # Soft delete
      t.datetime :discarded_at

      t.timestamps
    end

    add_index :users, :email, unique: true
    add_index :users, :pd_id, unique: true
    add_index :users, :username, unique: true
    add_index :users, :magic_link_token, unique: true
    add_index :users, :locked_at
    add_index :users, :last_api_activity_at
    add_index :users, :discarded_at

    # User sessions table
    create_table :user_sessions, id: :uuid do |t|
      t.uuid :user_id, null: false
      t.uuid :impersonated_by_id

      # Encrypted session token
      t.string :session_token_ciphertext
      t.string :session_token_bidx

      # Device and browser info
      t.string :fingerprint
      t.string :device_info
      t.string :os_info
      t.string :timezone

      # Network info
      t.string :ip
      t.float :latitude
      t.float :longitude

      # Session lifecycle
      t.datetime :expiration_at, null: false
      t.datetime :last_seen_at
      t.datetime :signed_out_at

      t.timestamps
    end

    add_index :user_sessions, :user_id
    add_index :user_sessions, :impersonated_by_id
    add_index :user_sessions, :session_token_bidx

    safety_assured do
      add_foreign_key :user_sessions, :users
      add_foreign_key :user_sessions, :users, column: :impersonated_by_id
    end

    # User API keys table
    create_table :user_api_keys, id: :uuid do |t|
      t.uuid :user_id, null: false
      t.string :name, null: false
      t.string :key_digest, null: false  # SHA256 hash of the API key

      t.datetime :last_used_at
      t.datetime :expires_at
      t.boolean :active, default: true, null: false

      # Soft delete
      t.datetime :discarded_at

      t.timestamps
    end

    add_index :user_api_keys, [:user_id, :active]
    add_index :user_api_keys, :key_digest, unique: true
    add_index :user_api_keys, :expires_at
    add_index :user_api_keys, :discarded_at

    safety_assured { add_foreign_key :user_api_keys, :users }
  end
end
