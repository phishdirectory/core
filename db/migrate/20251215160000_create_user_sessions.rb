class CreateUserSessions < ActiveRecord::Migration[8.1]
  def change
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

    add_foreign_key :user_sessions, :users
    add_foreign_key :user_sessions, :users, column: :impersonated_by_id
  end
end
