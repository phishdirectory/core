# frozen_string_literal: true

if Rails.env.development?
  LetterOpenerWeb.configure do |config|
    # Specify the location for storing letters (default is tmp/letter_opener)
    config.letters_location = Rails.root.join("tmp", "letter_opener")
  end
end
