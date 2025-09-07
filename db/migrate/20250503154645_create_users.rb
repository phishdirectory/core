# frozen_string_literal: true

class CreateUsers < ActiveRecord::Migration[8.0]
    def change
      create_enum 'access_level', [
        'owner',
        'superadmin',
        'admin',
        'trusted',
        'user'
      ]

      create_enum 'status', [
        'active',
        'suspended',
        'deactivated'
      ]

        create_table :users do |t|
            t.string :first_name, null: false
            t.string :last_name, null: false
            t.string :pd_id, null: false

            t.string :email, null: false
            t.boolean :email_verified, default: false
            t.datetime :email_verified_at

            t.string :password_digest, null: false

            t.column :access_level, :access_level, default: 'user', null: false
            t.column :api_access_level, :access_level, default: 'user', null: false

            t.boolean :pretend_is_not_admin, default: false, null: false
            t.integer :session_duration_seconds, default: 2592000, null: false

            t.column :status, :status, null: false, default: 'active'
            t.datetime :locked_at
            t.timestamps
        end

        add_index :users, :email, unique: true
        add_index :users, :pd_id, unique: true
    end
end
