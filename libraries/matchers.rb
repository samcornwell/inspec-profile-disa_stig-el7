# encoding: utf-8

RSpec::Matchers.define :match_pam_rule do |expected|
  match do |actual|
    if @negate_args_match || @args_operator
      retval = true
    else
      retval = false
    end

    actual_munge = {}

    @expected = expected.to_s

    if @args
      catch :stop_searching do
        actual.services.each do |service|
          expected_line = Pam::Rule.new(expected, {:service_name => service})

          potentials = actual.find_all do |line|
            line.match? expected_line
          end

          if potentials && !potentials.empty?
            actual_munge[service] ||= []
            actual_munge[service] += potentials.map(&:to_s)

            potentials.each do |potential|
              if @negate_args_match
                retval = !potential.module_arguments.join(' ').match(@args)
                throw :stop_searching unless retval
              elsif @args_operator
                module_int_args = potential.module_arguments.map { |a| a.split('=') }
                  .find_all { |a| a.length == 2 && a[1].match?(/^-?[0-9]+$/) }
                retval = module_int_args.any? {
                  |kv| (kv[0] == @args) && (kv[1].to_i.send @args_operator, @args_value)
                }
                throw :stop_searching unless retval
              else
                retval = !potential.module_arguments.join(' ').match(@args).nil?
                throw :stop_searching if retval
              end
            end
          end
        end
      end
    else
      retval = actual.include?(expected, {:service_name => actual.service})
    end

    if actual_munge.empty?
      @actual = actual.to_s
    elsif actual_munge.keys.length == 1
      @actual = actual_munge.values.flatten.join("\n")
    else
      @actual = actual_munge.map do |service, lines|
        lines.map do |line|
          service + ' ' + line
        end
      end.flatten.join("\n")
    end

    retval
  end

  diffable

  # TODO make these an array of args so that we can actually chain them together
  chain :any_with_args do |args|
    @args = args
  end

  chain :all_without_args do |args|
    @args = args
    @negate_args_match = true
  end

  chain :all_with_integer_arg do |key, op, value|
    @args = key
    @args_operator = op
    @args_value = value
  end

  description do
    res = "include #{expected}"
    if @args
      if @negate_args_match
        res += ", all without #{@args}"
      elsif @args_operator
        res += ", all with #{@args} #{@args_operator} #{@args_value}"
      else
        res += ", any with #{@args}"
      end
    end
    res
  end
end

RSpec::Matchers.define :match_pam_rules do |expected|
  match do |actual|
    @expected = expected.to_s
    @actual = actual.to_s

    if @exactly && actual.respond_to?(:include_exactly?)
      actual.include_exactly?(expected)
    else
      actual.include?(expected)
    end
  end

  diffable

  chain :exactly do
    @exactly = true
  end

  description do
    res = "include #{expected}"
    res += ' exactly' unless @exactly.nil?
    res
  end
end
