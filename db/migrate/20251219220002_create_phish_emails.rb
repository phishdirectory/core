# frozen_string_literal: true

class CreatePhishEmails < ActiveRecord::Migration[8.0]
  def change
    create_table :phish_emails, id: :uuid do |t|
      t.string :email, null: false # normalized email address
      t.string :domain # extracted domain part
      t.uuid :verdict_id
      t.datetime :last_checked_at
      t.datetime :last_seen_at

      # Email metadata
      t.boolean :disposable # is disposable/temporary email
      t.boolean :free_provider # is free email provider (gmail, yahoo, etc)
      t.boolean :deliverable # can receive email
      t.boolean :valid_mx # has valid MX records
      t.float :reputation_score # 0-1 reputation from services

      # Scam classification fields (same as domains/urls/phone_numbers)
      t.string :scam_category
      t.string :scam_subcategory
      t.datetime :marked_clean_at
      t.uuid :marked_clean_by_id

      t.datetime :discarded_at
      t.timestamps

      t.index :email, unique: true
      t.index :domain
      t.index :verdict_id
      t.index :last_checked_at
      t.index :last_seen_at
      t.index :disposable
      t.index :free_provider
      t.index :scam_category
      t.index :scam_subcategory
      t.index :marked_clean_at
      t.index :marked_clean_by_id
      t.index :discarded_at
    end

    # safety_assured: This is a new table with no existing data
    safety_assured do
      add_foreign_key :phish_emails, :verdicts
      add_foreign_key :phish_emails, :users, column: :marked_clean_by_id
    end
  end
end
