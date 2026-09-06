# frozen_string_literal: true

# Development seed data for Services
# Creates test services with API keys in various states
#
# Run with: bin/rails db:seed

module Seeds
  module DEVELOPMENT
    class Services
      TEST_SERVICES = [
        # Active services with keys
        {
          name: "Test Integration",
          status: :active,
          keys: [
            { notes: "Primary key", status: :active },
            { notes: "Secondary key", status: :active }
          ]
        },
        {
          name: "Mobile App",
          status: :active,
          keys: [
            { notes: "Production key", status: :active },
            { notes: "Old key (deprecated)", status: :deprecated }
          ]
        },
        {
          name: "Browser Extension",
          status: :active,
          keys: [
            { notes: "Extension key", status: :active }
          ]
        },

        # Suspended service
        {
          name: "Legacy System",
          status: :suspended,
          keys: [
            { notes: "Legacy key", status: :active }
          ]
        },

        # Decommissioned service
        {
          name: "Deprecated API",
          status: :decommissioned,
          keys: [
            { notes: "Revoked key", status: :revoked }
          ]
        }
      ].freeze

      def self.seed!
        puts "Seeding development services..."

        TEST_SERVICES.each do |data|
          service = Service.find_or_initialize_by(name: data[:name])

          if service.new_record?
            service.save!

            # Transition to correct status
            case data[:status]
            when :suspended
              service.suspend!
            when :decommissioned
              service.decommission!
            end

            # Create keys
            data[:keys].each do |key_data|
              key = service.service_keys.create!(notes: key_data[:notes])

              # Transition key to correct status
              case key_data[:status]
              when :deprecated
                key.deprecate!
              when :revoked
                key.revoke!
              end
            end

            puts "  + #{service.name} (#{service.status}, #{service.service_keys.count} keys)"
          else
            puts "  = #{service.name} (already exists)"
          end
        end

        puts "  Services by status:"
        puts "    - active: #{Service.active.count}"
        puts "    - suspended: #{Service.suspended.count}"
        puts "    - decommissioned: #{Service.decommissioned.count}"
        puts "  Total keys: #{Service::Key.count}"
      end
    end
  end
end
