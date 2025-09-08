# frozen_string_literal: true

class Phish::Domain < ApplicationRecord
  has_many :verdicts

end
