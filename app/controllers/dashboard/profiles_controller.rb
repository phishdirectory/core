# frozen_string_literal: true

module Dashboard
  class ProfilesController < BaseController
    def show
      @user = current_user
    end

    def edit
      @user = current_user
    end

    def update
      @user = current_user

      if @user.update(profile_params)
        redirect_to dashboard_profile_path, notice: "Profile updated successfully."
      else
        render :edit, status: :unprocessable_entity
      end
    end

    private

    def profile_params
      params.require(:user).permit(:first_name, :last_name, :profile_photo)
    end
  end
end
