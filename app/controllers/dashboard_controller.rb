# frozen_string_literal: true

class DashboardController < ApplicationController
  before_action :authenticate_user!

  def index
    @api_keys = current_user.user_api_keys.order(created_at: :desc)
    @total_keys = @api_keys.count
    @active_keys = @api_keys.active.count
    @expired_keys = @api_keys.expired.count
  end

end
