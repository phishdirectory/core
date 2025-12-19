# frozen_string_literal: true

class ValidatePhishTldsForeignKey < ActiveRecord::Migration[8.1]
  def change
    validate_foreign_key :phish_domains, :phish_tlds
  end
end
