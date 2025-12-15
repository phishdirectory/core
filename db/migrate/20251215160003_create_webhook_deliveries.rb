class CreateWebhookDeliveries < ActiveRecord::Migration[8.1]
  def change
    create_table :webhook_deliveries, id: :uuid do |t|
      t.string :url
      t.string :event
      t.text :payload
      t.string :status
      t.integer :attempts
      t.datetime :last_attempt_at
      t.jsonb :response

      t.timestamps
    end

    add_index :webhook_deliveries, :status
    add_index :webhook_deliveries, :event
  end
end
