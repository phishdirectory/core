class CreateUserSeenAtHistories < ActiveRecord::Migration[8.0]
  def change
    create_table :user_seen_at_histories, id: :uuid do |t|
      t.timestamps
    end
  end
end
