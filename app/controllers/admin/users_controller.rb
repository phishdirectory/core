# frozen_string_literal: true

module Admin
  class UsersController < BaseController
    before_action :set_user, except: [:index, :new, :create, :search]
    before_action :authorize_view!, only: [:show]
    before_action :authorize_manage!, only: [:edit, :update, :destroy, :impersonate, :suspend, :reactivate, :lock, :unlock, :make_admin, :remove_privileges]

    def index
      @users = User.order(created_at: :desc).page(params[:page])
    end

    def show
    end

    def new
      @user = User.new
    end

    def create
      @user = User.new(user_params)

      if @user.save
        redirect_to admin_user_path(@user), notice: "User created successfully."
      else
        render :new, status: :unprocessable_entity
      end
    end

    def edit
    end

    def update
      if @user.update(user_params)
        redirect_to admin_user_path(@user), notice: "User updated successfully."
      else
        render :edit, status: :unprocessable_entity
      end
    end

    def destroy
      if @user.destroy
        redirect_to admin_users_path, notice: "User deleted."
      else
        redirect_to admin_user_path(@user), alert: "Unable to delete user."
      end
    end

    def search
      @users = User.where("email ILIKE ? OR first_name ILIKE ? OR last_name ILIKE ?",
                          "%#{params[:q]}%", "%#{params[:q]}%", "%#{params[:q]}%")
                   .limit(20)
      render :index
    end

    # POST /admin/users/:id/impersonate
    def impersonate
      unless current_user.can_impersonate?
        redirect_to admin_user_path(@user), alert: "You cannot impersonate users."
        return
      end

      unless @user.impersonatable_by?(current_user)
        redirect_to admin_user_path(@user), alert: "You cannot impersonate this user."
        return
      end

      sign_in(@user, impersonator: current_user)
      redirect_to dashboard_root_path, notice: "Now impersonating #{@user.full_name}."
    end

    # POST /admin/users/:id/suspend
    def suspend
      if @user.may_suspend?
        @user.suspend!
        redirect_to admin_user_path(@user), notice: "User suspended."
      else
        redirect_to admin_user_path(@user), alert: "Cannot suspend this user."
      end
    end

    # POST /admin/users/:id/reactivate
    def reactivate
      if @user.may_reactivate?
        @user.reactivate!
        redirect_to admin_user_path(@user), notice: "User reactivated."
      else
        redirect_to admin_user_path(@user), alert: "Cannot reactivate this user."
      end
    end

    # POST /admin/users/:id/lock
    def lock
      @user.lock!
      redirect_to admin_user_path(@user), notice: "User account locked."
    end

    # POST /admin/users/:id/unlock
    def unlock
      @user.unlock!
      redirect_to admin_user_path(@user), notice: "User account unlocked."
    end

    # POST /admin/users/:id/make_admin
    def make_admin
      unless current_user.superadmin?
        redirect_to admin_user_path(@user), alert: "Only superadmins can promote users."
        return
      end

      @user.make_admin!
      redirect_to admin_user_path(@user), notice: "User promoted to admin."
    end

    # POST /admin/users/:id/remove_privileges
    def remove_privileges
      unless current_user.superadmin?
        redirect_to admin_user_path(@user), alert: "Only superadmins can remove privileges."
        return
      end

      @user.remove_privileges!
      redirect_to admin_user_path(@user), notice: "User privileges removed."
    end

    private

    def set_user
      @user = User.find(params[:id])
    end

    def authorize_view!
      unless @user.viewable_by?(current_user)
        redirect_to admin_users_path, alert: "You cannot view this user."
      end
    end

    def authorize_manage!
      unless @user.viewable_by?(current_user)
        redirect_to admin_users_path, alert: "You cannot manage this user."
      end
    end

    def user_params
      permitted = [:first_name, :last_name, :email, :profile_photo]
      permitted += [:access_level, :staff, :pd_dev] if current_user.superadmin?
      params.require(:user).permit(permitted)
    end
  end
end
