# frozen_string_literal: true

class User < ApplicationRecord
  include AASM
  include SoftDeletable
  include EncodedIds::HashidIdentifiable

  set_public_id_prefix "usr"

  has_paper_trail
  has_secure_password validations: false # Password is optional (magic links still work)

  # Associations
  has_many :visits, class_name: "Ahoy::Visit", dependent: :destroy
  has_many :user_sessions, class_name: "User::Session", dependent: :destroy
  has_many :user_api_keys, dependent: :destroy
  has_many :scam_classifications, class_name: "Scam::Classification", dependent: :destroy
  has_many :service_roles, class_name: "UserServiceRole", dependent: :destroy
  has_one_attached :profile_photo

  # Flipper integration - use pd_id for feature flags
  def flipper_id
    pd_id
  end

  # Access level configuration
  ACCESS_LEVELS = %w[user trusted admin superadmin owner].freeze

  enum :access_level, ACCESS_LEVELS.index_by(&:itself), scopes: false, default: :user

  # Callbacks
  before_validation :generate_pd_id, on: :create
  before_create :set_username
  after_update :notify_role_changes, if: :saved_change_to_access_level?
  after_create_commit :post_signup_tasks

  # Scopes
  scope :verified, -> { where(email_verified: true) }
  scope :unverified, -> { where(email_verified: false) }
  scope :last_seen_within, ->(ago) { joins(:user_sessions).where(user_sessions: { last_seen_at: ago.. }).distinct }
  scope :currently_online, -> { last_seen_within(15.minutes.ago) }
  scope :recently_active, -> { last_seen_within(30.days.ago) }

  # Role-based scopes
  scope :users_and_above, -> { where(access_level: %w[user trusted admin superadmin owner]) }
  scope :trusted_and_above, -> { where(access_level: %w[trusted admin superadmin owner]) }
  scope :admins_and_above, -> { where(access_level: %w[admin superadmin owner]) }
  scope :superadmins_and_above, -> { where(access_level: %w[superadmin owner]) }
  scope :owners_only, -> { where(access_level: "owner") }

  # Validations
  validates :first_name, presence: true
  validates :last_name, presence: true
  validates :email, presence: true, uniqueness: { case_sensitive: false }
  validates_email_format_of :email
  validates :email, 'valid_email_2/email': {
    disposable: true,
    message: "Sorry, but we do not accept disposable email providers."
  }
  normalizes :email, with: ->(email) { email.strip.downcase }

  validates :pd_id, presence: true, uniqueness: true, length: { is: 11 }, format: {
    with: /\APDU\d[a-zA-Z0-9]{7}\z/,
    message: "must be in the format PDU{digit}{7 alphanumeric characters}"
  }

  validates :magic_link_token, uniqueness: true, allow_nil: true
  validates :confirmation_token, uniqueness: true, allow_nil: true
  validates :password_reset_token, uniqueness: true, allow_nil: true

  # Password validation - only when password is being set
  validates :password, length: { minimum: 8 },
                       format: {
                         with: /\A(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+\[\]{}|;:'",.<>?\/`~]).+\z/,
                         message: "must include uppercase, lowercase, number, and special character"
                       },
                       if: -> { password.present? }

  validates :profile_photo,
            content_type: { in: %w[image/jpeg image/png image/webp], message: "must be a JPEG, PNG, or WebP image" },
            size: { less_than: 5.megabytes, message: "must be less than 5MB" },
            if: -> { profile_photo.attached? }

  # State machine for user status
  aasm column: :status do
    state :active, initial: true
    state :suspended
    state :deactivated

    event :suspend do
      transitions from: :active, to: :suspended
    end

    event :reactivate do
      transitions from: %i[suspended deactivated], to: :active
    end

    event :deactivate do
      transitions from: %i[active suspended], to: :deactivated
    end
  end

  # ===========================================
  # Role checking methods
  # ===========================================

  def trusted?
    return false if pretend_is_not_admin

    %w[trusted admin superadmin owner].include?(access_level)
  end

  def admin?
    return false if pretend_is_not_admin

    %w[admin superadmin owner].include?(access_level)
  end

  def superadmin?
    return false if pretend_is_not_admin

    %w[superadmin owner].include?(access_level)
  end

  def owner?
    return false if pretend_is_not_admin

    access_level == "owner"
  end

  def staff?
    staff
  end

  def pd_dev?
    pd_dev
  end

  # ===========================================
  # Role modification methods
  # ===========================================

  def make_trusted!
    update!(access_level: "trusted")
  end

  def make_admin!
    update!(access_level: "admin")
  end

  def make_superadmin!
    update!(access_level: "superadmin")
  end

  def make_owner!
    update!(access_level: "owner")
  end

  def remove_privileges!
    update!(access_level: "user")
  end

  # ===========================================
  # Authentication methods
  # ===========================================

  def can_authenticate?
    active? && !locked?
  end

  def locked?
    locked_at.present?
  end

  def lock!
    update!(locked_at: Time.current)
    user_sessions.destroy_all
  end

  def unlock!
    update!(locked_at: nil)
  end

  # ===========================================
  # Magic link authentication
  # ===========================================

  def generate_magic_link_token
    self.magic_link_token = SecureRandom.urlsafe_base64(32)
    self.magic_link_expires_at = 15.minutes.from_now
    self.magic_link_token_sent_at = Time.current
    self.magic_link_used_at = nil
    save!
  end

  def magic_link_valid?
    magic_link_token.present? &&
      magic_link_expires_at.present? &&
      magic_link_expires_at > Time.current &&
      magic_link_used_at.nil?
  end

  def consume_magic_link_token!
    return false unless magic_link_valid?

    self.magic_link_used_at = Time.current
    save!
    true
  end

  def send_magic_link
    generate_magic_link_token
    MagicLinkJob.perform_later(self)
  end

  # ===========================================
  # Password authentication
  # ===========================================

  def has_password?
    password_digest.present?
  end

  # ===========================================
  # Email confirmation
  # ===========================================

  def generate_confirmation_token
    self.confirmation_token = SecureRandom.urlsafe_base64(32)
    self.confirmation_sent_at = Time.current
    save!
  end

  def confirmation_token_valid?
    confirmation_token.present? &&
      confirmation_sent_at.present? &&
      confirmation_sent_at > 24.hours.ago &&
      confirmed_at.nil?
  end

  def confirm!
    update!(
      confirmed_at: Time.current,
      confirmation_token: nil,
      email_verified: true,
      email_verified_at: Time.current
    )
  end

  def confirmed?
    confirmed_at.present?
  end

  def send_confirmation_email
    generate_confirmation_token
    EmailConfirmationJob.perform_later(self)
  end

  # ===========================================
  # Password reset
  # ===========================================

  def generate_password_reset_token
    self.password_reset_token = SecureRandom.urlsafe_base64(32)
    self.password_reset_sent_at = Time.current
    self.password_reset_expires_at = 2.hours.from_now
    save!
  end

  def password_reset_token_valid?
    password_reset_token.present? &&
      password_reset_expires_at.present? &&
      password_reset_expires_at > Time.current
  end

  def reset_password!(new_password, new_password_confirmation)
    return false unless password_reset_token_valid?

    self.password = new_password
    self.password_confirmation = new_password_confirmation
    self.password_reset_token = nil
    self.password_reset_sent_at = nil
    self.password_reset_expires_at = nil
    save
  end

  def send_password_reset
    generate_password_reset_token
    PasswordResetJob.perform_later(self)
  end

  # ===========================================
  # Email verification
  # ===========================================

  def email_verified?
    email_verified
  end

  def verify_email!
    update!(email_verified: true, email_verified_at: Time.current)
  end

  def unverify_email!
    update!(email_verified: false, email_verified_at: nil)
  end

  # ===========================================
  # Name and identity helpers
  # ===========================================

  def full_name
    "#{first_name} #{last_name}"
  end

  def name
    full_name
  end

  def initials
    "#{first_name[0]}#{last_name[0]}".upcase
  end

  # ===========================================
  # Profile photo helpers
  # ===========================================

  def has_profile_photo?
    profile_photo.attached?
  end

  def profile_photo_url(variant: :thumb)
    return nil unless profile_photo.attached?

    case variant
    when :thumb
      profile_photo.variant(resize_to_limit: [100, 100])
    when :medium
      profile_photo.variant(resize_to_limit: [200, 200])
    when :large
      profile_photo.variant(resize_to_limit: [400, 400])
    else
      profile_photo
    end
  end

  # ===========================================
  # Session and activity tracking
  # ===========================================

  def last_seen_at
    user_sessions.maximum(:last_seen_at)
  end

  def last_login_at
    user_sessions.maximum(:created_at)
  end

  def recently_active?
    last_seen_at && last_seen_at >= 30.days.ago
  end

  def touch_api_activity!
    update!(last_api_activity_at: Time.current)
  end

  def recently_active_via_api?(threshold = 30.days)
    last_api_activity_at && last_api_activity_at >= threshold.ago
  end

  # ===========================================
  # Impersonation logic
  # ===========================================

  def can_impersonate?
    return false unless can_authenticate? && !pretend_is_not_admin

    admin?
  end

  def impersonatable_by?(impersonator)
    return false if self == impersonator

    case impersonator.access_level.to_sym
    when :owner
      true
    when :superadmin
      !owner?
    when :admin
      !admin?
    else
      false
    end
  end

  def viewable_by?(viewer)
    return true if self == viewer

    case viewer.access_level.to_sym
    when :owner
      true
    when :superadmin
      !owner?
    when :admin
      !admin?
    else
      false
    end
  end

  # ===========================================
  # Per-service role methods
  # ===========================================

  def role_for_service(service)
    service_roles.kept.find_by(service: service)&.role || access_level
  end

  def service_role_for(service)
    service_roles.kept.find_by(service: service)
  end

  def trusted_for_service?(service)
    %w[trusted admin superadmin owner].include?(role_for_service(service))
  end

  def admin_for_service?(service)
    %w[admin superadmin owner].include?(role_for_service(service))
  end

  def superadmin_for_service?(service)
    %w[superadmin owner].include?(role_for_service(service))
  end

  def owner_for_service?(service)
    role_for_service(service) == "owner"
  end

  def assign_service_role!(service, role, granted_by: nil)
    existing = service_roles.kept.find_by(service: service)
    if existing
      existing.promote_to!(role, by: granted_by)
    else
      service_roles.create!(service: service, role: role, granted_by: granted_by)
    end
  end

  def revoke_service_role!(service)
    service_roles.kept.find_by(service: service)&.discard
  end

  private

  # ===========================================
  # Callbacks
  # ===========================================

  def generate_pd_id
    return if pd_id.present?

    # Format: PDU{random digit}{7 random hex characters}
    # Example: PDU5A1B2C3D
    random_hex = SecureRandom.hex(4).upcase
    numeric_first = rand(10).to_s
    remaining_chars = random_hex[0...7]

    self.pd_id = "PDU#{numeric_first}#{remaining_chars}"
  end

  def set_username
    return if username.present?

    # Progressively build username: jmayone, jamayone, jasmayone, etc.
    (1..first_name.length).each do |i|
      candidate = "#{first_name[0, i].downcase}#{last_name.downcase}".gsub(/[^a-z0-9]/, "")
      unless User.exists?(username: candidate)
        self.username = candidate
        return
      end
    end

    # All options taken - queue job for ops to handle
    full_username = "#{first_name.downcase}#{last_name.downcase}".gsub(/[^a-z0-9]/, "")
    errors.add(:base, "Username conflict - our team will reach out within 24 hours.")
    UsernameFailJob.perform_later(email: email, desired_username: full_username)
    throw(:abort)
  end

  def notify_role_changes
    return unless saved_change_to_access_level?

    old_level, new_level = saved_change_to_access_level
    WebhookService.notify_user_role_changed(pd_id, new_level, old_level)
  end

  def post_signup_tasks
    WelcomeEmailJob.perform_later(self)
    NotifyOpsOnNewUserJob.perform_later(self)
  end
end
