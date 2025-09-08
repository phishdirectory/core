# frozen_string_literal: true

module Api
  module Entities
    class Domain < Base
      expose :domain
      expose :last_checked_at do |domain|
        domain.last_checked_at&.iso8601
      end

    end
  end
end
