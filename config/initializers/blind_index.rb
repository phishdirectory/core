# frozen_string_literal: true

# Blind Index configuration for searchable encryption
# Documentation: https://github.com/ankane/blind_index

raw_key = Rails.application.credentials.dig(:blind_index, :master_key) ||
          ENV["BLIND_INDEX_MASTER_KEY"] ||
          (raise "Missing Blind Index master key! Set credentials.blind_index.master_key or BLIND_INDEX_MASTER_KEY env var")

# BlindIndex requires exactly 32 bytes (64 hex chars)
# Truncate if key is longer (e.g., from a 64-byte key)
BlindIndex.master_key = raw_key[0, 64]
