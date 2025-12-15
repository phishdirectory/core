class CreateSessions < ActiveRecord::Migration[8.1]
  def change
    # Rails session store (for web sessions)
    create_table :sessions, id: :uuid do |t|
      t.string :session_id, null: false
      t.text :data

      t.timestamps
    end

    add_index :sessions, :session_id, unique: true
    add_index :sessions, :updated_at
  end
end
