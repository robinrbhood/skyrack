
require 'test/unit'

require 'skyrack/instr'


class TestInstr < Test::Unit::TestCase
		def setup
				Instr.cpu = Metasm::Ia32.new
				
		end
		def test_instr_decode
				nop = Instr.new("\x90")
				assert_equal nop.bin, "\x90"
				assert_equal nop.to_s, "nop"
				assert_not_equal nop.to_s, "nop2"
		end

		def test_assemble
				push_eax = Instr.assemble("push eax")
				assert_equal push_eax.bin, "P"
				nop = Instr.assemble("nop")
				assert_equal nop.bin, "\x90"
		end

		def test_args
				pop_eax = Instr.assemble("pop eax")
				assert_equal pop_eax.args.size, 1
				assert_equal pop_eax.args.first, Instr.str2reg("eax")


				push_esp = Instr.assemble("push esp")
				assert_equal push_esp.args.size, 1
				assert_equal push_esp.args.first, Instr.str2reg("esp")
				assert_equal push_esp.dst, Instr.str2reg("esp")
				assert_nil push_esp.src


				mov_eax_ebx = Instr.assemble("mov eax, ebx")
				
				assert_equal mov_eax_ebx.args.size, 2

				assert_equal mov_eax_ebx.src, Instr.str2reg("ebx")
				assert_equal mov_eax_ebx.dst, Instr.str2reg("eax")


			##mov_eax_0 = Instr.assemble("mov eax, 0")

			##assert_equal mov_eax_ebx.src, Instr.str2reg("ebx")
			##assert_equal mov_eax_ebx.dst, Instr.str2reg("eax")

		end
end
