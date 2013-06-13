
require 'yaml'
require 'skyrack/arbitrary_value'

class Functions
    FUNCTIONS_FILE = File.expand_path(File.join(__FILE__, '..', 'functions.yaml'))

    @@functions = YAML::load_file(FUNCTIONS_FILE)

    attr_reader :functions

    def self.functions
        @@functions
    end

    def self.valid?(fun)
        @@functions[:functions].include?(fun)
    end

    def initialize(db)
        @db = db
    end

    def set_to_arbitrary_value(value, dest)
        operations = {
            :inc       => @db.get_function(:add,  1, dest), # + 1
            :double    => @db.get_function(:mul,  2, dest), # * 2
            :init_zero => @db.get_function(:init, 0, dest), # = 0
        }

        set_reg(value).inject([]) { |a, e| a << [e, operations[e]] }
    end
end

