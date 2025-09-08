class Phish::Domain < ApplicationRecord
  has_many :verdicts
end
