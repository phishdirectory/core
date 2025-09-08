class CreateVerdicts < ActiveRecord::Migration[8.0]
  def change
    create_table :verdicts, id: :uuid do |t|
      t.timestamps
    end
  end
end
