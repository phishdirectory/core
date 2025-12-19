# frozen_string_literal: true

class CreateScamClassificationSystem < ActiveRecord::Migration[8.0]
  def change
    # Add scam classification fields to phish_domains
    add_column :phish_domains, :scam_category, :string
    add_column :phish_domains, :scam_subcategory, :string
    add_column :phish_domains, :marked_clean_at, :datetime
    add_column :phish_domains, :marked_clean_by_id, :uuid

    # Add scam classification fields to phish_urls
    add_column :phish_urls, :scam_category, :string
    add_column :phish_urls, :scam_subcategory, :string
    add_column :phish_urls, :marked_clean_at, :datetime
    add_column :phish_urls, :marked_clean_by_id, :uuid

    # Create scam_classifications table for user votes
    create_table :scam_classifications, id: :uuid do |t|
      # Polymorphic association to classifiable (domain, url, etc.)
      t.string :classifiable_type, null: false
      t.uuid :classifiable_id, null: false

      # User who made the classification
      t.uuid :user_id, null: false

      # Classification details
      t.string :scam_category, null: false
      t.string :scam_subcategory
      t.text :notes

      t.timestamps

      # Indexes for scam_classifications (added in create_table for new table)
      t.index [ :classifiable_type, :classifiable_id ], name: "index_scam_classifications_on_classifiable"
      t.index :user_id
      t.index :scam_category
      t.index :scam_subcategory
      t.index [ :user_id, :classifiable_type, :classifiable_id ],
              unique: true,
              name: "index_scam_classifications_on_user_and_classifiable"
    end

    # Indexes for existing tables - use safety_assured since these are new columns with no data
    safety_assured do
      add_index :phish_domains, :scam_category
      add_index :phish_domains, :scam_subcategory
      add_index :phish_domains, :marked_clean_at
      add_index :phish_domains, :marked_clean_by_id

      add_index :phish_urls, :scam_category
      add_index :phish_urls, :scam_subcategory
      add_index :phish_urls, :marked_clean_at
      add_index :phish_urls, :marked_clean_by_id
    end
  end
end
