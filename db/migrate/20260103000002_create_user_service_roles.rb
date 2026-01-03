# frozen_string_literal: true

class CreateUserServiceRoles < ActiveRecord::Migration[8.1]
  def change
    create_table :user_service_roles, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      t.references :user, type: :uuid, null: false, foreign_key: true
      t.references :service, type: :uuid, null: false, foreign_key: true
      t.enum :role, enum_type: "access_level", null: false, default: "user"
      t.datetime :granted_at
      t.references :granted_by, type: :uuid, foreign_key: { to_table: :users }
      t.datetime :discarded_at

      t.timestamps
    end

    add_index :user_service_roles, %i[user_id service_id], unique: true, where: "discarded_at IS NULL"
    add_index :user_service_roles, :discarded_at
    add_index :user_service_roles, :role
  end
end
