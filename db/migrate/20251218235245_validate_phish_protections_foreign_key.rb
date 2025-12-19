class ValidatePhishProtectionsForeignKey < ActiveRecord::Migration[8.1]
  def change
    validate_foreign_key :phish_protections, :users
  end
end
