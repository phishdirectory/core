# frozen_string_literal: true

module Dashboard
  class DashboardController < BaseController
    def index
      @api_keys = current_user.user_api_keys.order(created_at: :desc).limit(5)
      @recent_sessions = current_user.user_sessions.active.order(created_at: :desc).limit(5)
    end
  end
end
