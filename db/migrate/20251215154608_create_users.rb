class CreateUsers < ActiveRecord::Migration[8.1]
  def change
    # Enable PostgreSQL extensions
    enable_extension "pgcrypto" unless extension_enabled?("pgcrypto")
    enable_extension "fuzzystrmatch" unless extension_enabled?("fuzzystrmatch")

    # Create enums
    create_enum "access_level", %w[owner superadmin admin trusted user]
    create_enum "status", %w[active suspended deactivated]

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

      t.timestamps
    end

    add_index :users, :email, unique: true
    add_index :users, :pd_id, unique: true
    add_index :users, :username, unique: true
    add_index :users, :magic_link_token, unique: true
    add_index :users, :locked_at
  end
end
