class CreateUserApiKeys < ActiveRecord::Migration[8.1]
  def change
    create_table :user_api_keys, id: :uuid do |t|
      t.uuid :user_id, null: false
      t.string :name, null: false
      t.string :key_digest, null: false  # SHA256 hash of the API key

      t.datetime :last_used_at
      t.datetime :expires_at
      t.boolean :active, default: true, null: false

      t.timestamps
    end

    add_index :user_api_keys, :user_id
    add_index :user_api_keys, [:user_id, :active]
    add_index :user_api_keys, :key_digest, unique: true
    add_index :user_api_keys, :expires_at

    add_foreign_key :user_api_keys, :users
  end
end
