
require 'metasm'

class String
    def indexes(pat)
        res = []
        ind = -1
        while ind = self.index(pat, ind + 1) do
            res << ind
        end
        res
    end
end

class Fixnum
    def addr
        [self].pack( Instr.cpu.size == 32 ? 'L' : 'Q' )
    end

end

class Instr
    include Comparable
    @@cpu = Metasm::Ia32.new

    attr_accessor :instr, :addr, :bin, :bin_length, :bin_str, :size, :dis, :cpu

    def initialize(raw, addr=0)
        @instr, @dis = Instr.decode(raw)
        raise Metasm::Exception.new("could not generate instruction with binary '%s' @0x%08x" % [raw.unpack('H*'), addr]) unless @instr
        @addr = addr
        @bin  = raw
        @size = @bin.size
        @bin_length = @size
    end

    def args
        @instr.instruction.args
        # @instr.opcode.args
    end

    def next_instr_addr
        addr + bin_length
    end

    # decodes the current string as a Shellcode, with specified base address
    # returns the resulting Disassembler
    def self.decode(str, base_addr=0, eip=base_addr)
        return false unless str
        res = @@cpu.decode_instruction Metasm::EncodedData.new(str), eip	
        res.nil? || res.bin_length != str.size ? false : res
    end

    def self.decode_with_dis(str, base_addr=0, eip=base_addr)
        res = false
        dis = nil
        begin
            sc = Metasm::Shellcode.decode(str, @@cpu)
            sc.base_addr = base_addr
            # FIXME sc.disassemble_fast(eip)
            dis = sc.disassemble(eip)
            res = dis.decoded[0]
            return false if res.nil? or res.bin_length != str.size
        rescue Metasm::Exception, NoMethodError => e
            puts "Error: #{e.class} #{e.message} with %s" % str.unpack('C*').map {|s| s.to_s(16)}.inspect if $verbosity > 1
        end
        return res, dis
    end

    def self.assemble(str, address = 0)
        begin
            s = Metasm::Shellcode.assemble @@cpu, str
        rescue Metasm::ParseError => e
            puts e.to_s
            return nil
        end
        enc = s.encoded
        enc.fill
        Instr.new(enc.data, address)
    end

    def self.as(*args); self.assemble(*args); end

    def self.from_db_row(row)
        bin = [row['bin']].pack('H*')
        addr = row['address']
        return self.new(bin, addr)
    end

    def to_s(full=false)
        if not full
            return @instr.to_s.gsub(/;.*$/, '').gsub(/^0/, '').strip
        else
            return "0x%06x\t%s\t%s" % [addr, bin_str, to_s(false)]
        end
    end

    def src
        a = @instr.instruction.args
        a.size == 2 ? a[1] : nil
    end

    def dst
        a = @instr.instruction.args
        a.size >= 1 ? a[0] : nil
    end

    def modify_reg(test_reg)
        (dst.is_a?(@@cpu.class::Reg) &&
         test_reg.is_a?(@@cpu.class::Reg)) ?
         dst.share?(test_reg) : false
    end

    def <=>(i2)
        @addr <=> i2.addr
    end

    def self.str2reg(str)
        reg.from_str(str)
    end

    def self.cpu() @@cpu end

    def self.cpu=(c=nil)
        if c.kind_of? String
            c = Metasm.const_get(c).new 
            c = c.new
        end
        @@cpu=c
    end

    def self.reg
        @@cpu.class::Reg
    end

    def expr
        @expr ||= @@cpu.get_backtrace_binding(instr)
    end

end

