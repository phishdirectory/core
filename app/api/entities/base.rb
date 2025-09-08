# frozen_string_literal: true

module Entities
  class Base < Grape::Entity
    format_with :iso8601 do |datetime|
      datetime&.iso8601
    end
  end
end