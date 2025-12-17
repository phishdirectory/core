# frozen_string_literal: true

# Route constraint for admin-only routes
# Usage in routes.rb:
#   constraints AdminConstraint.new do
#     mount Flipper::UI.app => "/flipper"
#   end
#
# Or with minimum access level:
#   constraints AdminConstraint.new(minimum_level: :superadmin) do
#     mount MissionControl::Jobs::Engine => "/jobs"
#   end

class AdminConstraint
  ACCESS_HIERARCHY = {
    user: 0,
    trusted: 1,
    admin: 2,
    superadmin: 3,
    owner: 4
  }.freeze

  def initialize(minimum_level: :admin)
    @minimum_level = minimum_level
  end

  def matches?(request)
    session_token = request.session[:session_token]
    return false unless session_token.present?

    # Authenticate via User::Session (same as ApplicationController)
    user_session = User::Session.authenticate(session_token)
    return false unless user_session

    user = user_session.user
    return false unless user&.can_authenticate?

    user_level = ACCESS_HIERARCHY[user.access_level.to_sym] || 0
    required_level = ACCESS_HIERARCHY[@minimum_level] || 2

    user_level >= required_level
  end
end
