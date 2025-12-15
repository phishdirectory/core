class CreatePhishTables < ActiveRecord::Migration[8.1]
  def change
    # Verdicts table (the phishing verdict/classification)
    create_table :verdicts, id: :uuid do |t|
      t.string :classification  # e.g., "phishing", "clean", "suspicious"
      t.float :confidence_score
      t.jsonb :sources          # Which services flagged it
      t.jsonb :metadata

      t.timestamps
    end

    # Phish domains table
    create_table :phish_domains, id: :uuid do |t|
      t.string :domain, null: false
      t.datetime :last_checked_at
      t.uuid :verdict_id

      t.timestamps
    end

    add_index :phish_domains, :domain, unique: true
    add_index :phish_domains, :verdict_id
    add_index :phish_domains, :last_checked_at

    add_foreign_key :phish_domains, :verdicts

    # Phish URLs table
    create_table :phish_urls, id: :uuid do |t|
      t.string :url, null: false
      t.datetime :last_checked_at
      t.uuid :verdict_id

      t.timestamps
    end

    add_index :phish_urls, :url, unique: true
    add_index :phish_urls, :verdict_id
    add_index :phish_urls, :last_checked_at

    add_foreign_key :phish_urls, :verdicts
  end
end
