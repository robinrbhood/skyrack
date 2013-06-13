require 'skyrack/instr'

class Gadget < Array
    attr_accessor :base_addr, :dis, :expr

    def initialize(*args)
        if args.size > 0 && args.first.is_a?(String) then
            str_dis = Gadget.dis_from_str(args.first)
            res = super(str_dis.decoded.values)
            res.dis = str_dis
            return res
        else
            super(*args)
        end
    end

    # to build with strings such as "mov eax, 1; nop; ret"
    def self.from_str(str)
        Gadget.new( str.split(';').inject([]) { |a, instr| a << Instr.as(instr) } )
    end

    def expr
        @expr ||= Instr.cpu.code_binding(dis, 0)
    end

    def dis=(v)
        @dis = v
    end

    def dis(base_addr=0, eip=base_addr)
        if @dis then
            @dis
        else
            eip = 0
            str = inject("") 	{ |str, instr| str << instr.bin }
            @dis = Gadget.dis_from_str(str, base_addr, eip)
        end
    end

    def	self.dis_from_str(raw, base_addr=0, eip=base_addr)
        sc = Metasm::Shellcode.decode(raw, Instr.cpu)
        sc.base_addr = base_addr
        # FIXME sc.disassemble_fast(eip)
        sc.disassemble(eip)
    end

    # an instruction gadget can be found equal to an other one only and only if
    # the sequence of the instructions is the same
    include Comparable

    def <=>(gadget)
        return (size <=> gadget.size) unless size == gadget.size
        same_gadgets = true
        for i in 0...size
            same_gadgets &= (self[i].bin == gadget[i].bin)
            return 1 unless same_gadgets
        end
        return 0
    end

    def base_addr
        @base_addr ||= self.first.addr
    end

    def modify_regs(reg_gadget)
        reg_gadget.inject(false) 	{ |b, reg| b |= modify_reg(reg) }
    end

    def preserve_regs(reg_gadget)
        not modify_regs(reg_gadget)
    end

    def modify_reg(reg, idx = 0)
        self[idx..-1].inject(false) { |s, i| s |= i.modify_reg(reg) }
    end

    def preserve_target?
        target = first.dst
        not modify_reg(target, 1)
    end

    def preserve_eip?
        not self[1..-2].inject(false) { |s, i| op = i.instr.opcode.props;  s |= (op[:setip] || op[:stopexec]) } 
    end

    def to_s
        res = ["====== 0x%x ======" % base_addr]
        each do |i|
            res << "%s" % i.to_s(true)
        end
        return res.join("\n")
    end

    # returns true only if the argument is included in the current gadget
    # (no order)
    def include_gadget?(gadget)
        return false if self.size < gadget.size
        inject(true) { |b, element| b &= gadget.include? element }
    end

    # returns true only if the argument is a subset of the current gadget
    # (same order)
    def include_gadget?(gadget)
        return false if self.size < gadget.size
        res = true
        each_with_index do |idx, e|
            res &= (gadget[idx] == e)
        end
    end

    def get_binding
        cpu = first.cpu
        binding = nil
        self.each do |instr|
            binding = cpu.get_backtrace_binding(instr)
        end
    end

end


