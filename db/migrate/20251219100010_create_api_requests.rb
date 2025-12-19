# frozen_string_literal: true

class CreateApiRequests < ActiveRecord::Migration[8.1]
  def change
    create_table :api_requests, id: :uuid do |t|
      # Polymorphic association for the authenticating key (UserApiKey or Service::Key)
      t.references :authenticatable, polymorphic: true, type: :uuid, index: true

      # Optional user reference (for service keys acting on behalf of users)
      t.references :user, type: :uuid, index: true

      # Request details
      t.string :request_path, null: false
      t.string :request_method, null: false, limit: 10
      t.string :ip_address
      t.text :user_agent
      t.text :request_headers
      t.text :request_body

      # Response details
      t.integer :response_code
      t.text :response_body

      # Performance metrics
      t.integer :duration_ms

      # Timing
      t.datetime :requested_at, null: false

      t.timestamps
    end

    add_index :api_requests, :requested_at
    add_index :api_requests, :response_code
    add_index :api_requests, :duration_ms
    add_index :api_requests, [:authenticatable_type, :authenticatable_id, :requested_at],
              name: "idx_api_requests_auth_time"

    safety_assured { add_foreign_key :api_requests, :users, on_delete: :nullify }
  end
end
