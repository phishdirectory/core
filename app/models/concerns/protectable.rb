# frozen_string_literal: true

module Protectable
  extend ActiveSupport::Concern

  included do
    # Class method to check if a value is protected
    def self.value_protected?(value)
      Phish::Protection.protected?(name, value)
    end

    # Class method to get the protection record for a value
    def self.protection_for(value)
      Phish::Protection.protection_for(name, value)
    end
  end

  # Check if this instance is protected
  def protected?
    self.class.value_protected?(protectable_value)
  end

  # Get the protection record for this instance
  def protection
    self.class.protection_for(protectable_value)
  end

  private

  # Subclasses must define this to return the value to check for protection
  def protectable_value
    raise NotImplementedError, "#{self.class.name} must define #protectable_value"
  end
end
