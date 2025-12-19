# frozen_string_literal: true

# Seed data for Phish::Protection
# Pre-populates protection for major legitimate domains that should never be flagged as phishing
#
# Run with: bin/rails db:seed

module Seeds
  class Protections
    PROTECTED_DOMAINS = [
      # Major tech companies
      { value: "google.com", reason: "Major search engine and technology company" },
      { value: "microsoft.com", reason: "Major technology company" },
      { value: "apple.com", reason: "Major technology company" },
      { value: "amazon.com", reason: "Major e-commerce and cloud company" },
      { value: "meta.com", reason: "Major social media company (formerly Facebook)" },
      { value: "facebook.com", reason: "Major social media platform" },
      { value: "twitter.com", reason: "Major social media platform" },
      { value: "x.com", reason: "Major social media platform (formerly Twitter)" },
      { value: "linkedin.com", reason: "Professional networking platform" },
      { value: "instagram.com", reason: "Major social media platform" },

      # Cloud providers
      { value: "aws.amazon.com", reason: "Amazon Web Services cloud platform" },
      { value: "azure.microsoft.com", reason: "Microsoft Azure cloud platform" },
      { value: "cloud.google.com", reason: "Google Cloud Platform" },
      { value: "cloudflare.com", reason: "Major CDN and security provider" },

      # Development platforms
      { value: "github.com", reason: "Major code hosting platform" },
      { value: "gitlab.com", reason: "Major code hosting platform" },
      { value: "bitbucket.org", reason: "Code hosting platform" },
      { value: "stackoverflow.com", reason: "Developer Q&A platform" },
      { value: "npmjs.com", reason: "Node.js package registry" },
      { value: "rubygems.org", reason: "Ruby package registry" },
      { value: "pypi.org", reason: "Python package registry" },

      # Financial services
      { value: "paypal.com", reason: "Major payment platform" },
      { value: "stripe.com", reason: "Payment processing platform" },
      { value: "square.com", reason: "Payment processing platform" },
      { value: "venmo.com", reason: "Payment platform" },

      # Communication services
      { value: "zoom.us", reason: "Video conferencing platform" },
      { value: "slack.com", reason: "Team communication platform" },
      { value: "discord.com", reason: "Communication platform" },
      { value: "teams.microsoft.com", reason: "Microsoft Teams communication platform" },

      # Email providers
      { value: "gmail.com", reason: "Google email service" },
      { value: "outlook.com", reason: "Microsoft email service" },
      { value: "proton.me", reason: "Secure email service" },
      { value: "protonmail.com", reason: "Secure email service" },

      # Security vendors
      { value: "virustotal.com", reason: "Security scanning platform" },
      { value: "phish.directory", reason: "Phishing detection service (us)" },

      # Other major services
      { value: "dropbox.com", reason: "Cloud storage platform" },
      { value: "netflix.com", reason: "Streaming platform" },
      { value: "spotify.com", reason: "Music streaming platform" },
      { value: "youtube.com", reason: "Video streaming platform" },
      { value: "reddit.com", reason: "Social news platform" },
      { value: "wikipedia.org", reason: "Online encyclopedia" }
    ].freeze

    def self.seed!
      puts "Seeding protected domains..."

      # Find or create a system user for seeded protections
      system_user = User.find_by(email: "system@phish.directory")
      unless system_user
        puts "  Warning: No system user found. Skipping protections seeding."
        puts "  Create a user with email 'system@phish.directory' to enable seeding."
        return
      end

      created = 0
      skipped = 0

      PROTECTED_DOMAINS.each do |attrs|
        if Phish::Protection.exists?(protectable_type: "Phish::Domain", protectable_value: attrs[:value])
          skipped += 1
          next
        end

        Phish::Protection.create!(
          protectable_type: "Phish::Domain",
          protectable_value: attrs[:value],
          reason: attrs[:reason],
          protected_by: system_user
        )
        created += 1
      end

      puts "Protected domains: #{created} created, #{skipped} skipped (#{PROTECTED_DOMAINS.size} total)"
    end
  end
end
