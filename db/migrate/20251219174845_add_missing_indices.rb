class AddMissingIndices < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    # Add index on user_sessions.last_seen_at for User#last_seen_at queries
    add_index :user_sessions, [:user_id, :last_seen_at],
              name: "index_user_sessions_on_user_id_and_last_seen_at",
              if_not_exists: true,
              algorithm: :concurrently
  end
end
