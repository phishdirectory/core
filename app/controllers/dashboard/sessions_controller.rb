# frozen_string_literal: true

module Dashboard
  class SessionsController < BaseController
    def index
      @sessions = current_user.user_sessions.order(created_at: :desc)
      @current_session = current_session
    end

    def destroy
      user_session = current_user.user_sessions.find(params[:id])

      if user_session == current_session
        redirect_to dashboard_sessions_path, alert: "You cannot terminate your current session from here. Use logout instead."
        return
      end

      user_session.sign_out!
      redirect_to dashboard_sessions_path, notice: "Session terminated."
    end
  end
end
