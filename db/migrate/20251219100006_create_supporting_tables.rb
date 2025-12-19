# frozen_string_literal: true

class CreateSupportingTables < ActiveRecord::Migration[8.1]
  def change
    # Lockbox audits (encryption access logging)
    create_table :lockbox_audits, id: :uuid do |t|
      t.string :subject_type
      t.uuid :subject_id
      t.string :viewer_type
      t.uuid :viewer_id
      t.jsonb :data
      t.string :context
      t.string :ip

      t.datetime :created_at
    end

    add_index :lockbox_audits, [:subject_type, :subject_id]
    add_index :lockbox_audits, [:viewer_type, :viewer_id]

    # Paper Trail versions (audit log)
    create_table :versions, id: :uuid do |t|
      t.string :whodunnit
      t.datetime :created_at
      t.uuid :item_id, null: false
      t.string :item_type, null: false
      t.string :event, null: false
      t.text :object
      t.text :object_changes
    end

    add_index :versions, [:item_type, :item_id]
    add_index :versions, :created_at

    # Friendly ID slugs
    create_table :friendly_id_slugs, id: :uuid do |t|
      t.string :slug, null: false
      t.uuid :sluggable_id, null: false
      t.string :sluggable_type, limit: 50
      t.string :scope

      t.datetime :created_at
    end

    add_index :friendly_id_slugs, [:slug, :sluggable_type, :scope], unique: true
    add_index :friendly_id_slugs, [:sluggable_type, :sluggable_id]

    # PG Search documents
    create_table :pg_search_documents, id: :uuid do |t|
      t.text :content
      t.string :searchable_type
      t.uuid :searchable_id

      t.timestamps
    end

    add_index :pg_search_documents, [:searchable_type, :searchable_id]

    # Rollups (time-series metrics)
    create_table :rollups, id: :uuid do |t|
      t.string :name, null: false
      t.string :interval, null: false
      t.datetime :time, null: false
      t.jsonb :dimensions, default: {}, null: false
      t.float :value
    end

    add_index :rollups, [:name, :interval, :time, :dimensions], unique: true

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

    # Blazer queries
    create_table :blazer_queries, id: :uuid do |t|
      t.uuid :creator_id
      t.string :name
      t.text :description
      t.text :statement
      t.string :data_source
      t.string :status

      t.timestamps
    end

    add_index :blazer_queries, :creator_id

    # Blazer audits
    create_table :blazer_audits, id: :uuid do |t|
      t.uuid :user_id
      t.uuid :query_id
      t.text :statement
      t.string :data_source

      t.datetime :created_at
    end

    add_index :blazer_audits, :user_id
    add_index :blazer_audits, :query_id

    # Blazer dashboards
    create_table :blazer_dashboards, id: :uuid do |t|
      t.uuid :creator_id
      t.string :name

      t.timestamps
    end

    add_index :blazer_dashboards, :creator_id

    # Blazer dashboard queries (join table)
    create_table :blazer_dashboard_queries, id: :uuid do |t|
      t.uuid :dashboard_id
      t.uuid :query_id
      t.integer :position

      t.timestamps
    end

    add_index :blazer_dashboard_queries, :dashboard_id
    add_index :blazer_dashboard_queries, :query_id

    # Blazer checks (scheduled alerts)
    create_table :blazer_checks, id: :uuid do |t|
      t.uuid :creator_id
      t.uuid :query_id
      t.string :state
      t.string :schedule
      t.text :emails
      t.text :slack_channels
      t.string :check_type
      t.text :message
      t.datetime :last_run_at

      t.timestamps
    end

    add_index :blazer_checks, :creator_id
    add_index :blazer_checks, :query_id

    # Blazer uploads
    create_table :blazer_uploads, id: :uuid do |t|
      t.uuid :creator_id
      t.string :table
      t.text :description

      t.timestamps
    end

    add_index :blazer_uploads, :creator_id
  end
end
