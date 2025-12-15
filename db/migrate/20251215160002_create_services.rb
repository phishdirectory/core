class CreateServices < ActiveRecord::Migration[8.1]
  def change
    # Service status enum
    create_enum "service_status", %w[active suspended decommissioned]
    create_enum "service_key_status", %w[active deprecated revoked]

    # Services table
    create_table :services, id: :uuid do |t|
      t.string :name, null: false
      t.column :status, :service_status, default: "active", null: false
      t.integer :keys_count, default: 0, null: false

      t.timestamps
    end

    add_index :services, :name, unique: true

    # Service keys table
    create_table :service_keys, id: :uuid do |t|
      t.uuid :service_id, null: false
      t.string :api_key, null: false     # 48 hex chars
      t.string :hash_key, null: false    # 64 hex chars for encryption
      t.column :status, :service_key_status, default: "active", null: false
      t.text :notes

      t.timestamps
    end

    add_index :service_keys, :service_id
    add_index :service_keys, :api_key, unique: true

    add_foreign_key :service_keys, :services

    # Service webhooks table
    create_table :service_webhooks, id: :uuid do |t|
      t.uuid :service_id, null: false
      t.string :url, null: false
      t.string :secret, null: false

      t.timestamps
    end

    add_index :service_webhooks, :service_id
    add_index :service_webhooks, :url, unique: true

    add_foreign_key :service_webhooks, :services

    # Service key usages table (API request logging)
    create_table :service_key_usages, id: :uuid do |t|
      t.uuid :key_id, null: false
      t.uuid :user_id  # nullable - tracks which user the service was operating as

      # Request info
      t.string :request_path
      t.string :request_method
      t.string :ip_address
      t.text :user_agent
      t.text :request_headers
      t.text :request_body
      t.datetime :requested_at

      # Response info
      t.integer :response_code
      t.text :response_body
      t.text :response_headers

      # Performance
      t.integer :duration_ms

      t.timestamps
    end

    add_index :service_key_usages, :key_id
    add_index :service_key_usages, :user_id
    add_index :service_key_usages, :requested_at
    add_index :service_key_usages, :duration_ms

    add_foreign_key :service_key_usages, :service_keys, column: :key_id
    add_foreign_key :service_key_usages, :users, on_delete: :nullify
  end
end
