class CreateConsoleAuditTables < ActiveRecord::Migration[8.1]
  def change
    # Console1984 users (console session users)
    create_table :console1984_users, id: :uuid do |t|
      t.string :username, null: false

      t.timestamps
    end

    add_index :console1984_users, :username

    # Console1984 sessions
    create_table :console1984_sessions, id: :uuid do |t|
      t.text :reason
      t.uuid :user_id, null: false

      t.timestamps
    end

    add_index :console1984_sessions, :created_at
    add_index :console1984_sessions, [:user_id, :created_at]

    # Console1984 sensitive accesses
    create_table :console1984_sensitive_accesses, id: :uuid do |t|
      t.text :justification
      t.uuid :session_id, null: false

      t.timestamps
    end

    add_index :console1984_sensitive_accesses, :session_id

    # Console1984 commands
    create_table :console1984_commands, id: :uuid do |t|
      t.text :statements
      t.uuid :sensitive_access_id
      t.uuid :session_id, null: false

      t.timestamps
    end

    add_index :console1984_commands, :sensitive_access_id
    add_index :console1984_commands, [:session_id, :created_at, :sensitive_access_id],
              name: "on_session_and_sensitive_chronologically"

    # Audits1984 audits
    create_table :audits1984_audits, id: :uuid do |t|
      t.integer :status, default: 0, null: false
      t.text :notes
      t.uuid :session_id, null: false
      t.uuid :auditor_id, null: false

      t.timestamps
    end

    add_index :audits1984_audits, :session_id
    add_index :audits1984_audits, :auditor_id
  end
end
