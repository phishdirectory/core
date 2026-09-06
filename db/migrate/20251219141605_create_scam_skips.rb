# frozen_string_literal: true

class CreateScamSkips < ActiveRecord::Migration[8.0]
  def change
    create_table :scam_skips, id: :uuid do |t|
      # Polymorphic association to classifiable (domain, url, etc.)
      t.string :classifiable_type, null: false
      t.uuid :classifiable_id, null: false

      # User who skipped
      t.uuid :user_id, null: false

      t.timestamps

      t.index [ :classifiable_type, :classifiable_id ], name: "index_scam_skips_on_classifiable"
      t.index :user_id
      t.index [ :user_id, :classifiable_type, :classifiable_id ], name: "index_scam_skips_on_user_and_classifiable"
    end
  end
end
