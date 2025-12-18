# frozen_string_literal: true

class AddLastApiActivityAtToUsers < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_column :users, :last_api_activity_at, :datetime
    add_index :users, :last_api_activity_at, algorithm: :concurrently
  end
end
