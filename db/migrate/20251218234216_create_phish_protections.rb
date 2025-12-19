class CreatePhishProtections < ActiveRecord::Migration[8.1]
  def change
    create_table :phish_protections, id: :uuid do |t|
      t.string :protectable_type, null: false
      t.string :protectable_value, null: false
      t.text :reason
      t.uuid :protected_by_id, null: false
      t.datetime :discarded_at

      t.timestamps
    end

    add_index :phish_protections, [:protectable_type, :protectable_value], unique: true, name: "index_protections_on_type_and_value"
    add_index :phish_protections, :protected_by_id
    add_index :phish_protections, :discarded_at
    add_foreign_key :phish_protections, :users, column: :protected_by_id, validate: false
  end
end
