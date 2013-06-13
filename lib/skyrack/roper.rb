require 'skyrack/instr'

begin
    require 'metasm'
rescue LoadError => e
    puts e.inspect, ""
    puts "You have to use metasm and to run %s with metasm path:" % $0
    puts "  $ RUBYLIB=/path/to/metasm/ ruby %s bin.exe" % $0
end

$verbosity = 0

include Metasm

module RopSection

    RETS = {0xC3 => { :name => 'ret',  :binsize => 1},
        0xC2 => { :name => 'reti', :binsize => 3}}

    #FIXME use real data
    SIZES = (1..7)

    attr_accessor :bin, :deepness

    def cpu; bin.cpu; end

    def each_gadget(deepness)
        @deepness = deepness
        each_ret_addr do |ret|
            @cur_ret += 1
            puts "%-10s @0x%008x [%d / %d]" % [ret.to_s, ret.addr, @cur_ret, @nb_ret] #if $verbosity > 0
            find_gadgets_ending_at(ret) do |g|
                yield(g, ret.addr)
            end
        end
    end

    def get_addr_of(hex)
        bin_data().indexes(hex.chr).map { |addr| instr_addr(addr) }
    end

    def each_ret_addr
        @nb_ret = 0
        @cur_ret = 0

        RETS.each do |hex, info|
            indexes = get_addr_of(hex)
            @nb_ret += indexes.size
            puts "[x] found %d ret (%x)" % [indexes.size, hex]
            indexes.each do |addr|

                bin = bin_data[abs_addr_to_rel(addr), info[:binsize]]
                r = Instr.new(bin, addr)
                raise "error generating ret 0x%x" % addr unless r
                yield(r)
            end
        end
    end

    def find_gadgets_ending_at(root_instr, deepness = @deepness)
        graph = GadgetTree[]

        # fills the graph:
        instr_paths(root_instr, graph, deepness)

        (block_given? ? yield(graph) : graph)
    end

    def instr_paths(prev_instr, graph, deepness = @deepness)
        return if deepness == 0
        for instr in instrs_ending_at(prev_instr.addr - 1, graph)

            next if graph.has_edge?(prev_instr, instr)

            graph.add_edge(prev_instr, instr) 
            instr_paths(instr, graph, deepness - 1)
        end
    end

    # returns instruction whose last byte is at addr
    def instrs_ending_at(addr, graph)
        instrs = []
        end_addr = abs_addr_to_rel(addr)
        for size in SIZES do
            start_addr = addr - size + 1
            next if start_addr < 0 or graph.include_addr?(start_addr)

            # we have to translate addresses from memory to section data
            raw = bin_data[abs_addr_to_rel(start_addr)..end_addr]
            begin
                instr = Instr.new(raw, start_addr)
            rescue Metasm::Exception
                next
            end
            next unless instr
            puts "@0x%08x %s" % [addr, instr.to_s] if $verbosity > 1
            instrs << instr
        end
        return instrs
    end

    def interesting_jmps
        raise "fixme"
    end

    def bin_data
        self.encoded.data 
    end

    def to_s
        if respond_to? :size then
            "[0x%08x] %s (%d)" % [base_addr, name, size]
        else
            "[0x%08x] %s" % [base_addr, name]
        end
    end
end

class Metasm::ExeFormat
    def each_executable_section
        sky_each_section { |s, addr| puts s.class; yield(s, addr) if s.executable? }
    end

    def each_gadget_graph(depth = 5)
        each_executable_section do |s, s_addr|
            puts "%10s 0x%06x" % [s.name, s_addr]
            s.each_gadget(depth) do |g, addr|
                yield(g, addr)
            end
        end
    end

    def find_gadgets_ending_at(addr, depth = 5)
        sky_each_section do |s, s_addr|
            puts "looking for %x in %s 0x%x (0x%x)" % [addr, s.name, s_addr, (s.bin_data ? s_addr + s.bin_data.size : nil)] if $verbosity > 2
            if s.bin_data && ((s_addr <= addr)) && ((s_addr + s.bin_data.size) >= addr)
                puts "0x%x found in %s 0x%x" % [addr, s.name, s_addr]
                tried_size = 0
                opc = false
                begin
                    raw = s.bin_data[addr..(addr+tried_size)]
                    opc, = Instr.new(raw,  s.instr_addr(addr))
                end while !opc && tried_size < 10
                if opc
                    puts "found instr %s" % opc
                    return s.find_gadgets_ending_at(opc, depth) 
                else
                    puts "no valid instruction found at 0x%x: %s" % [addr, raw.unpack('C*').inspect]  unless opc
                end
            end
        end
        return nil
    end

    def search_str(str)
        sky_each_section do |s, s_addr|
            s.bin_data.indexes(str).each do |idx|
                yield(s.instr_addr(idx))
            end
        end
    end

    def search_raw(regexp)
        sky_each_section do |s, s_addr|
            s.bin_data.indexes(regexp).each do |idx|
                m = regexp.match(s.bin_data[idx..-1])
                yield(s.instr_addr(idx), m[0])
            end
        end
    end
end

class Metasm::ELF

    def base_addr
        header.entry
    end

    def sky_each_section
        #decode
        iterator = case header.type
                   when 'DYN', 'EXEC'
                       segments
                   when 'REL'
                       sections
                   end
        iterator.each do |s|
            if s.encoded.nil? # skip first empty section
                puts "empty %s" % s.class if $verbosity > 0
                next 
            end
            s.bin = self
            yield(s, s.base_addr())
        end
    end 

    module SectionOrSegment
        include RopSection
        def instr_addr(i_addr)
            i_addr + base_addr
        end

        def abs_addr_to_rel(i_addr)
            i_addr - base_addr
        end
    end

    class Section 
        include SectionOrSegment 

        def executable?
            flags.include? "EXECINSTR"
        end
        def base_addr
            addr
        end
    end
    class Segment
        include SectionOrSegment 
        def executable?
            flags.include? "X"
        end
        def name
            "%s %s" % [flags.inspect, base_addr]
        end
        def base_addr
            vaddr
        end
    end
end

class Metasm::COFF
    def sky_each_section
        sections.each do |s|
            s.bin = self
            yield(s, s.base_addr())
        end
    end 

    def base_addr
        optheader.image_base
    end

    class Section
        include RopSection
        def instr_addr(i_addr)
            i_addr + bin.base_addr + self.base_addr
        end

        def abs_addr_to_rel(i_addr)
            i_addr - bin.base_addr - self.base_addr
        end

        def executable?
            @characteristics.include? 'MEM_EXECUTE'	
        end
        def base_addr
            virtaddr
        end
        def size
            virtsize
        end
    end
end
class Metasm::MachO
    def sky_each_section
        #decode 
        segments.each do |s|
            s.bin = self
            yield(s, s.base_addr)
        end
    end
    class LoadCommand::SEGMENT
        include RopSection
        def executable?
            maxprot.include? 'EXECUTE'	
        end
        def base_addr
            virtaddr
        end
        def instr_addr(i_addr)
            i_addr + base_addr
        end

        def abs_addr_to_rel(i_addr)
            i_addr - base_addr
        end
    end
end

