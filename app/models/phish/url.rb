# frozen_string_literal: true

class Phish::Url < ApplicationRecord
  has_many :verdicts, dependent: :destroy

end
