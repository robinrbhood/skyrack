
require 'skyrack/gadget'

class Payload < Array

    def to_s
        inject([]) { |a, gadget| a << gadget.to_s }.join("\n")
    end

    def to_b(offset = 0, addr_size = 32)
        # FIXME addr size depending on CPU by gadget
        pack_target = (addr_size == 32 ? 'L' : 'Q')
        inject([]) { |a, gadget| a << gadget.base_addr + offset}.pack("%s*" % pack_target)
    end
end

class Payloads < Array
    attr_accessor :addr_size

    def initialize(size, *args)
        raise "size error" unless [32, 64].include? size
        @@addr_size = size	
        super(*args)
    end

    # returns the final binary string
    def to_b(offset = 0)
        pack_target = (@@addr_size == 32 ? 'L' : 'Q')
        inject('') { |a, payload|
            a << (
                case payload
                when Payload
                    payload.to_b(offset, @@addr_size)
                when String
                    payload
                when Fixnum
                    [payload + offset].pack("%s*" % pack_target)
                end
            ) }
    end

    def to_s
        inject([]) { |a, gadget| a << gadget.to_s }.join("\n")
    end

    def self.generate(file, db)
        p = Payloads.new(db.cpu.size)
        parse_file(file) do |st, type, l|
            p << self.parse_statement(st, type, db)
        end
        p
    end

    def self.parse_file(file, only_utils = true)
        File.open(file, 'r') do |f|
            f.each_line do |l|
                parse_line(l, only_utils) { |st, type| yield(st, type, l) }
            end
        end
    end

    def self.parse_str(str)
        str.each_line do |l|
            parse_line(l) { |st, type| yield(st, type) }
        end
    end

    def self.parse_line(l, only_utils = true)
        l = l.strip
        l = ' ' if l[0].nil?
        case l[0].chr
        when '!'
            yield([l[1..-1], 0], :ruby)
        when '@'
            yield(l[1..-1], :address)
        when '?'
            yield(l[1..-1].split, :function)
        when '#', ' '
            only_utils ? return : yield(l, :comment_or_empty) 
        else
            yield(l.split, :gadget)
        end
    end

    def self.parse_statement(st, type, db = nil)
        res = nil
        case type
        when :gadget
            # "@0xff" -> 0xff
            addr_str = st.first.split('0x')[1]
            addr_int = addr_str.to_i(16)
            # payloads << addr_int
            res = addr_int
        when :function
            raise "you should provide db to use functions" if db.nil?
            fun   = st[0].to_sym
            dest  = st[1]
            value = st[2]
            #        payloads << db.get_function(fun, value, dest) 
            res = db.get_function(fun, value, dest) 
        when :ruby
            ruby_str, lineno = st
            begin
                res = eval(ruby_str)
            rescue Exception => e
                $stderr.puts "error on line %d:%s" % [lineno, ruby_str]
            end

            raise "Statement should return String (instead of %s): !%s" % [res.class, st] unless res.is_a? String
            #payloads << res
            #			when :address
            #					# payloads << db.get_address(st)
            #					yield(db.get_address(st))
        when :comment_or_empty
            st
        end
        return res
    end

    # translates addresses of exploit_file to offsets from db_dst
    def self.translate_file(exploit_file, db_dst)
        new_file = []
        parse_file(exploit_file, false) do |st, type, l|
            case type
            when :gadget
                res = find_same_gadget(st, db_dst)
                if res
                    new_file << "# previous statement: %s" % l.strip
                    # FIXME use returned gadget .to_s like rather than st
                    new_file << "%06x %s" % [res.base_addr, st[1..-1].join(' ')]
                else
                    new_file << "# found no equivalent to %s\n" % l.strip
                end
            else
                new_file << l.strip
            end
        end
        return new_file
    end

    def self.find_same_gadget(st, db_dst)
        g = Gadget.from_str(st[1..-1].join(' '))
        return ( g ? db_dst.find_equivalent(g) : nil )
    end
end
