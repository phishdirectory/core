class CreateUserApiKeys < ActiveRecord::Migration[8.0]
  def change
    create_table :user_api_keys do |t|
      t.references :user, null: false, foreign_key: true
      t.string :name, null: false
      t.string :key_digest, null: false
      t.datetime :last_used_at
      t.datetime :expires_at
      t.boolean :active, default: true, null: false

      t.timestamps
    end

    add_index :user_api_keys, :key_digest, unique: true
    add_index :user_api_keys, [:user_id, :active]
    add_index :user_api_keys, :expires_at
  end
end
