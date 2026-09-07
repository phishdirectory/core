# frozen_string_literal: true

module Iok
  # Parses and evaluates the `condition` line of an IOK detection block.
  #
  # IOK rules are Sigma rules, so the condition is a small boolean expression
  # over the named selections in the same block:
  #
  #   condition: title and meta and (favicon or form)
  #   condition: notfoundPageFragments and (1 of php*)
  #   condition: all of them
  #
  # Grammar:
  #
  #   expression := or_expression
  #   or_expression  := and_expression ( "or" and_expression )*
  #   and_expression := unary ( "and" unary )*
  #   unary          := "not" unary | primary
  #   primary        := "(" expression ")" | quantifier | identifier
  #   quantifier     := ( integer | "all" | "any" ) "of" ( "them" | pattern )
  #
  # `all` and `any` are only keywords when followed by `of`, so a selection may
  # legitimately be named `all`.
  class Condition
    class ParseError < StandardError; end

    # Matches an identifier, a glob pattern, or a number. Selection names in
    # the corpus are alphanumeric; `*`, `?` and `[]` appear in glob patterns.
    WORD = /[A-Za-z0-9_.*?\[\]\-]+/
    TOKEN = /\(|\)|#{WORD}/

    KEYWORDS = %w[and or not of them].freeze
    QUANTIFIERS = %w[all any].freeze

    attr_reader :source

    # @param source [String, Array<String>] the condition line, or several of
    #   them. Sigma treats a list of conditions as an OR.
    def initialize(source)
      @source = source
      @ast = build_ast(source)
    end

    # @param context [#matched?, #names] resolves selection names to booleans
    #   and lists every selection name in the detection block.
    # @return [Boolean]
    def matches?(context)
      @ast.call(context)
    end

    # Every selection name the condition refers to by name (not by pattern).
    # Used to reject rules that point at a selection which does not exist.
    def referenced_names
      @ast.referenced_names
    end

    private

    def build_ast(source)
      expressions = Array(source).map { |line| parse_one(line) }
      raise ParseError, "condition is empty" if expressions.empty?
      return expressions.first if expressions.one?

      Node::Or.new(expressions)
    end

    def parse_one(line)
      raise ParseError, "condition is not a string" unless line.is_a?(String)

      tokens = tokenize(line)
      raise ParseError, "condition is empty" if tokens.empty?

      parser = Parser.new(tokens)
      node = parser.parse_expression
      parser.expect_end!
      node
    end

    def tokenize(line)
      remainder = line.dup
      tokens = []

      until remainder.blank?
        remainder = remainder.lstrip
        break if remainder.empty?

        match = remainder.match(/\A#{TOKEN}/)
        raise ParseError, "unexpected character in condition: #{remainder[0].inspect}" unless match

        tokens << match[0]
        remainder = match.post_match
      end

      tokens
    end

    # Recursive descent over the token list.
    class Parser
      def initialize(tokens)
        @tokens = tokens
        @position = 0
      end

      def parse_expression
        parse_or
      end

      def expect_end!
        return if @position >= @tokens.length

        raise ParseError, "unexpected token #{peek.inspect} in condition"
      end

      private

      def parse_or
        nodes = [ parse_and ]
        nodes << parse_and while consume_keyword("or")
        nodes.one? ? nodes.first : Node::Or.new(nodes)
      end

      def parse_and
        nodes = [ parse_unary ]
        nodes << parse_unary while consume_keyword("and")
        nodes.one? ? nodes.first : Node::And.new(nodes)
      end

      def parse_unary
        return Node::Not.new(parse_unary) if consume_keyword("not")

        parse_primary
      end

      def parse_primary
        if consume("(")
          node = parse_or
          raise ParseError, "unbalanced parentheses in condition" unless consume(")")

          return node
        end

        token = advance
        raise ParseError, "unexpected end of condition" if token.nil?

        quantifier_for(token) || identifier_for(token)
      end

      # `all of them`, `1 of them`, `all of php*`. The quantifier word is only a
      # keyword when `of` follows it, so `all` on its own stays a selection name.
      def quantifier_for(token)
        return nil unless quantifier?(token)
        return nil unless keyword?(peek, "of")

        advance # consume "of"
        target = advance
        raise ParseError, "expected a selection name or `them` after `of`" if target.nil?

        Node::Quantifier.new(
          minimum: minimum_for(token),
          pattern: keyword?(target, "them") ? nil : target
        )
      end

      def identifier_for(token)
        if KEYWORDS.include?(token.downcase)
          raise ParseError, "unexpected keyword #{token.inspect} in condition"
        end

        Node::Identifier.new(token)
      end

      def quantifier?(token)
        QUANTIFIERS.include?(token.downcase) || token.match?(/\A\d+\z/)
      end

      # `all of` means every matching selection. `any of` and `N of` mean at
      # least N, which Node::Quantifier represents as a minimum count.
      def minimum_for(token)
        case token.downcase
        when "all" then :all
        when "any" then 1
        else token.to_i
        end
      end

      def peek
        @tokens[@position]
      end

      def advance
        token = @tokens[@position]
        @position += 1
        token
      end

      def consume(literal)
        return false unless peek == literal

        @position += 1
        true
      end

      def consume_keyword(keyword)
        return false unless keyword?(peek, keyword)

        @position += 1
        true
      end

      def keyword?(token, keyword)
        token.is_a?(String) && token.downcase == keyword
      end
    end

    module Node
      class Base
        def referenced_names
          []
        end
      end

      class And < Base
        def initialize(nodes)
          @nodes = nodes
        end

        def call(context)
          @nodes.all? { |node| node.call(context) }
        end

        def referenced_names
          @nodes.flat_map(&:referenced_names)
        end
      end

      class Or < Base
        def initialize(nodes)
          @nodes = nodes
        end

        def call(context)
          @nodes.any? { |node| node.call(context) }
        end

        def referenced_names
          @nodes.flat_map(&:referenced_names)
        end
      end

      class Not < Base
        def initialize(node)
          @node = node
        end

        def call(context)
          !@node.call(context)
        end

        def referenced_names
          @node.referenced_names
        end
      end

      class Identifier < Base
        attr_reader :name

        def initialize(name)
          @name = name
        end

        def call(context)
          context.matched?(@name)
        end

        def referenced_names
          [ @name ]
        end
      end

      # `all of them`, `1 of them`, `all of php*`, `1 of php*`.
      #
      # A nil pattern means "them", every selection in the block. Sigma's
      # `all of <pattern>` is vacuously true when no selection name matches the
      # pattern, which mirrors the upstream Go evaluator.
      class Quantifier < Base
        def initialize(minimum:, pattern:)
          @minimum = minimum
          @pattern = pattern
        end

        def call(context)
          names = selected_names(context)
          hits = names.count { |name| context.matched?(name) }

          @minimum == :all ? hits == names.length : hits >= @minimum
        end

        private

        def selected_names(context)
          return context.names if @pattern.nil?

          # File::FNM_PATHNAME keeps `*` from crossing a `/`, which is what Go's
          # path.Match does in the upstream evaluator.
          context.names.select { |name| File.fnmatch?(@pattern, name, File::FNM_PATHNAME) }
        end
      end
    end
  end
end
