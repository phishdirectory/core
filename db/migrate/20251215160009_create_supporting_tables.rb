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
    add_index :friendly_id_slugs, [:slug, :sluggable_type]
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
  end
end
