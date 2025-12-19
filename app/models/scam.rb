# frozen_string_literal: true

# Namespace module for scam classification system.
# Contains the scam taxonomy and classification-related models.
module Scam
  # Scam Taxonomy - Categories and Subcategories with descriptions
  # Based on comprehensive scam classification research
  TAXONOMY = {
    "impersonation" => {
      name: "Impersonation Scams",
      description: "Scammers pretend to be someone the victim trusts, such as tech support, government officials, or family members.",
      subcategories: {
        "tech_support" => "Fake technical support claiming your device has issues",
        "government_official" => "Impersonating IRS, SSA, police, or other officials",
        "celebrity_influencer" => "Fake celebrity accounts or endorsements",
        "friend_family" => "Posing as friends or family members",
        "model_photographer" => "Fake modeling agencies or photographers",
        "account_recovery" => "Pretending to help recover hacked accounts",
        "bank_financial" => "Impersonating banks or financial institutions",
        "utility_provider" => "Posing as utility companies"
      }
    },
    "social_engineering" => {
      name: "Social Engineering & Messaging Scams",
      description: "Building fake relationships or using social manipulation to extract money or information.",
      subcategories: {
        "romance" => "Fake romantic relationships to extract money",
        "pig_butchering" => "Long-term grooming for crypto/investment fraud",
        "wrong_number" => "Accidental text messages that start scam conversations",
        "friendship" => "Fake friendship building for eventual scam",
        "emergency_grandparent" => "Claiming a grandchild is in trouble",
        "military_romance" => "Using fake military personas for romance scams"
      }
    },
    "credential_theft" => {
      name: "Credential Theft Scams",
      description: "Attempts to steal login credentials, passwords, or sensitive personal information.",
      subcategories: {
        "phishing_email" => "Fraudulent emails requesting login credentials",
        "smishing_sms" => "Text message-based phishing attacks",
        "vishing_voice" => "Phone call-based phishing attempts",
        "spear_phishing" => "Targeted phishing using personal information",
        "whaling" => "Phishing targeting executives or high-value individuals",
        "qr_code" => "Malicious QR codes leading to fake login pages",
        "fake_login_page" => "Counterfeit websites mimicking legitimate logins"
      }
    },
    "financial_crypto" => {
      name: "Financial & Crypto Scams",
      description: "Fraudulent investment opportunities, cryptocurrency schemes, and financial fraud.",
      subcategories: {
        "advance_fee" => "Requiring upfront payment to receive larger sums",
        "check_overpayment" => "Sending fake checks for more than owed",
        "wire_transfer" => "Urgently requesting wire transfers",
        "cryptocurrency_investment" => "Fake crypto investment platforms",
        "pump_and_dump" => "Artificially inflating then selling assets",
        "rug_pull" => "Abandoning crypto projects after collecting funds",
        "fake_exchange" => "Counterfeit cryptocurrency exchanges",
        "recovery_room" => "Claiming to recover lost funds for a fee",
        "loan_fee" => "Requiring fees before loan approval",
        "pyramid_scheme" => "Multi-level schemes requiring recruitment",
        "forex_trading" => "Fraudulent foreign exchange platforms",
        "binary_options" => "Rigged binary options trading platforms"
      }
    },
    "job_employment" => {
      name: "Job & Employment Scams",
      description: "Fake job opportunities designed to steal money or personal information.",
      subcategories: {
        "fake_job_offer" => "Non-existent job positions",
        "work_from_home" => "Too-good-to-be-true remote work offers",
        "reshipping_mule" => "Using victims to reship stolen goods",
        "task_scam" => "Fake task/review work requiring payment",
        "mlm_recruitment" => "Predatory multi-level marketing recruitment",
        "interview_fee" => "Requiring payment for job interviews"
      }
    },
    "gaming" => {
      name: "Gaming Platform Scams",
      description: "Scams targeting gamers through fake trades, currency, or accounts.",
      subcategories: {
        "steam_trade" => "Fraudulent Steam item trades",
        "roblox_robux" => "Fake Robux generators or giveaways",
        "skin_gambling" => "Rigged gaming skin gambling sites",
        "account_theft" => "Stealing gaming accounts for resale",
        "cheat_malware" => "Game cheats containing malware"
      }
    },
    "creative_commission" => {
      name: "Creative & Commission Scams",
      description: "Fraud targeting artists and creators through fake commissions.",
      subcategories: {
        "art_commission" => "Fake art buyers using chargebacks",
        "design_work" => "Fraudulent design or graphics work requests",
        "content_creation" => "Fake influencer collaboration offers"
      }
    },
    "shopping" => {
      name: "Online Shopping Scams",
      description: "Fake stores, counterfeit goods, and fraudulent marketplace listings.",
      subcategories: {
        "fake_storefront" => "Counterfeit e-commerce websites",
        "counterfeit_goods" => "Selling fake branded products",
        "non_delivery" => "Taking payment but never shipping items",
        "dropshipping_fraud" => "Overpriced items from dropshipping",
        "craigslist_marketplace" => "Scams on local marketplaces",
        "ticket_scalping" => "Fake event tickets",
        "puppy_pet" => "Non-existent pets or breeders",
        "vehicle_sale" => "Fraudulent vehicle listings",
        "electronics_deal" => "Too-good-to-be-true electronics offers",
        "designer_replica" => "Fake luxury goods as authentic",
        "subscription_trap" => "Hidden recurring charges"
      }
    },
    "rental_realestate" => {
      name: "Rental & Real Estate Scams",
      description: "Fake rental listings and real estate fraud.",
      subcategories: {
        "rental_listing" => "Non-existent rental properties",
        "vacation_rental" => "Fake vacation rental listings"
      }
    },
    "urgent_payment" => {
      name: "Urgent Payment Scams",
      description: "Creating false urgency to pressure immediate payment.",
      subcategories: {
        "irs_tax" => "Fake IRS or tax authority demands",
        "warrant_arrest" => "Threatening arrest without payment",
        "utility_shutoff" => "Fake utility disconnection threats",
        "gift_card_demand" => "Demanding gift cards as payment",
        "boss_ceo_wire" => "Impersonating executives requesting wire transfers",
        "kidnapping_ransom" => "Fake kidnapping ransom demands",
        "customs_package" => "Fake customs fees for packages",
        "debt_collection" => "Fraudulent debt collection"
      }
    },
    "extortion" => {
      name: "Extortion, Blackmail & Sextortion",
      description: "Threatening to release information unless payment is made.",
      subcategories: {
        "sextortion" => "Threatening to release intimate images",
        "webcam_blackmail" => "Claiming to have recorded webcam footage",
        "data_breach_threat" => "Threatening to release stolen data",
        "ransomware" => "Encrypting files and demanding payment",
        "hitman_threat" => "Fake assassination threat demands"
      }
    },
    "miscellaneous" => {
      name: "Miscellaneous & Global Scams",
      description: "Classic advance-fee and international fraud schemes.",
      subcategories: {
        "nigerian_419" => "Classic advance-fee fraud emails",
        "lottery_prize" => "Fake lottery or prize winnings",
        "inheritance" => "Fake inheritance from unknown relatives",
        "charity_disaster" => "Fake charities exploiting disasters"
      }
    }
  }.freeze

  CATEGORIES = TAXONOMY.keys.freeze
  SUBCATEGORIES = TAXONOMY.values.flat_map { |v| v[:subcategories].keys }.freeze

  class << self
    def category_name(category)
      TAXONOMY.dig(category, :name)
    end

    def category_description(category)
      TAXONOMY.dig(category, :description)
    end

    def subcategories_for(category)
      TAXONOMY.dig(category, :subcategories)&.keys || []
    end

    def subcategory_description(category, subcategory)
      TAXONOMY.dig(category, :subcategories, subcategory)
    end

    def valid_category?(category)
      CATEGORIES.include?(category)
    end

    def valid_subcategory?(category, subcategory)
      TAXONOMY.dig(category, :subcategories)&.key?(subcategory) || false
    end

    # Get taxonomy for UI (including descriptions)
    def taxonomy_for_select
      TAXONOMY.map do |key, data|
        {
          value: key,
          label: data[:name],
          description: data[:description],
          subcategories: data[:subcategories].map { |sub_key, sub_desc|
            { value: sub_key, label: sub_key.titleize, description: sub_desc }
          }
        }
      end
    end

    # Get full taxonomy data for modal/documentation
    def taxonomy_with_descriptions
      TAXONOMY.transform_values do |data|
        {
          name: data[:name],
          description: data[:description],
          subcategories: data[:subcategories]
        }
      end
    end
  end
end
