# frozen_string_literal: true

class InitialsAvatarService
  # Colors for avatar backgrounds - phish.directory brand palette
  COLORS = %w[
    #3FC4E0
    #10B981
    #F59E0B
    #EF4444
    #8B5CF6
    #EC4899
    #06B6D4
    #84CC16
  ].freeze

  class << self
    # Generate an SVG avatar with initials
    #
    # @param initials [String] 1-2 character initials
    # @param size [Integer] Size in pixels (default: 100)
    # @return [String] SVG markup
    def generate(initials, size: 100)
      initials = initials.to_s.upcase[0, 2]
      bg_color = color_for_initials(initials)
      font_size = (size * 0.4).round

      <<~SVG
        <svg xmlns="http://www.w3.org/2000/svg" width="#{size}" height="#{size}" viewBox="0 0 #{size} #{size}">
          <rect width="100%" height="100%" fill="#{bg_color}" rx="#{size / 2}"/>
          <text x="50%" y="50%" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="#{font_size}" font-weight="600" fill="white" text-anchor="middle" dominant-baseline="central">#{initials}</text>
        </svg>
      SVG
    end

    # Generate a square avatar (non-circular)
    #
    # @param initials [String] 1-2 character initials
    # @param size [Integer] Size in pixels
    # @return [String] SVG markup
    def generate_square(initials, size: 100)
      initials = initials.to_s.upcase[0, 2]
      bg_color = color_for_initials(initials)
      font_size = (size * 0.4).round
      corner_radius = (size * 0.1).round

      <<~SVG
        <svg xmlns="http://www.w3.org/2000/svg" width="#{size}" height="#{size}" viewBox="0 0 #{size} #{size}">
          <rect width="100%" height="100%" fill="#{bg_color}" rx="#{corner_radius}"/>
          <text x="50%" y="50%" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="#{font_size}" font-weight="600" fill="white" text-anchor="middle" dominant-baseline="central">#{initials}</text>
        </svg>
      SVG
    end

    private

    # Deterministically select a color based on initials
    def color_for_initials(initials)
      # Use a hash of the initials to pick a consistent color
      hash = initials.to_s.bytes.sum
      COLORS[hash % COLORS.length]
    end
  end
end
