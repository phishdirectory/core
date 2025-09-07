# frozen_string_literal: true

# app/controllers/concerns/ensure_enabled.rb
module EnsureEnabled
  extend ActiveSupport::Concern

  class FeatureDisabled < StandardError
    attr_reader :feature, :actor

    def initialize(message = nil, feature: nil, actor: nil)
      super(message)
      @feature = feature
      @actor = actor
    end

  end

  included do
    # Usage: before_action -> { ensure_enabled!(:my_feature) }
    rescue_from FeatureDisabled, with: :feature_disabled_response
  end

  private

  # Checks if the given Flipper feature is enabled.
  # Raises FeatureDisabled if not.
  #
  # @param feature [Symbol, String] The Flipper feature name
  # @param actor [Object, nil] Optionally pass an actor for per-user features
  def ensure_enabled!(feature, actor: nil)
    enabled = if actor
                Flipper.enabled?(feature, actor)
              else
                Flipper.enabled?(feature)
              end

    raise FeatureDisabled.new("Feature '#{feature}' is disabled", feature: feature, actor: actor) unless enabled
  end

  # Override this method in your controller to customize the response
  def feature_disabled_response(exception = nil)
    @disabled_feature = exception&.feature
    @disabled_actor = exception&.actor
    render "errors/feature_disabled", status: :forbidden, layout: false
  end
end
