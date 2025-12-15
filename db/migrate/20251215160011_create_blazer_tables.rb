class CreateBlazerTables < ActiveRecord::Migration[8.1]
  def change
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
