class CreatePhishDomains < ActiveRecord::Migration[8.0]
  def change
    create_table :phish_domains, id: :uuid do |t|
      t.string :domain
      t.datetime :last_checked_at
      t.references :verdict, foreign_key: { to_table: :verdicts }, type: :uuid
      t.timestamps
    end
  end
end
