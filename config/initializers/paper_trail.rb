# frozen_string_literal: true

# Paper Trail configuration for audit logging
# Documentation: https://github.com/paper-trail-gem/paper_trail

PaperTrail.config.enabled = true

# Store the type of the object being versioned
PaperTrail.config.object_changes_adapter = nil

# Use UUID for version IDs (matches our UUID primary keys)
# PaperTrail.config.version_class_name = "PaperTrail::Version"

# Serialize object and object_changes as JSON instead of YAML
PaperTrail.serializer = PaperTrail::Serializers::JSON

# Track who made changes (set in ApplicationController)
# PaperTrail.request.whodunnit = -> { Current.user&.pd_id }
