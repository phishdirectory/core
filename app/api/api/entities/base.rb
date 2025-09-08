# frozen_string_literal: true

module Api
  module Entities
    class Base < Grape::Entity
      include GrapeRouteHelpers::NamedRouteMatcher

      format_with(:iso_timestamp) { |dt| dt&.iso8601 }

      def self.format_as_date(&block)
        with_options(format_with: :iso_timestamp, &block)
      end

      def self.entity_name
        self.name.demodulize.titleize
      end

      delegate :object_type, to: :class

      def self.object_type
        self.entity_name.gsub(" ", "_").underscore
      end

      def self.api_self_path_method_name
        "api_v1_#{self.object_type.pluralize}_path"
      end


    end
  end
end
