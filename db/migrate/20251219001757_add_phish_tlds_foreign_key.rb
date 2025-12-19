# frozen_string_literal: true

class AddPhishTldsForeignKey < ActiveRecord::Migration[8.1]
  def change
    add_foreign_key :phish_domains, :phish_tlds, column: :tld_id, validate: false
  end
end
