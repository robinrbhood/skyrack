
require 'test/unit'

require 'skyrack/gadget'


class TestInstr < Test::Unit::TestCase
		def setup
				Instr.cpu = Metasm::Ia32.new
		end

		def test_gadget_eql

			g1 = Gadget.new [Instr.as("push eax"), Instr.as("push esp"), Instr.as("ret")]
			g2 = Gadget.new [Instr.as("push eax"), Instr.as("push esp"), Instr.as("ret")]
			g3 = Gadget.new [Instr.as("push eax")] + [Instr.as("push eax"), Instr.as("push esp"), Instr.as("ret")]

			assert_equal(3, g1.size)
			assert_equal(4, g3.size)

			assert_equal(Gadget, g1.class)
			assert_equal(g1, g2)
			assert_equal(g1 == g2, true)
			assert_not_equal(g2, g3)
			assert_equal(g2 == g3, false)
		end

		def test_constructor
				is = []
				is << Instr.as("mov ecx, edx")
				is << Instr.as("mov ebx, 0")
				is << Instr.as("mov eax, ebx")
				is << Instr.as("add eax, 2")
				is << Instr.as("sal eax, 1")
				is << Instr.as("ret")
				raw = is.map 	{ |i| i.bin }.join
				g = Gadget.new(raw)

				assert_equal 4, g.expr[:eax].reduce
				assert_equal 0, g.expr[:ebx].reduce
				assert_equal Metasm::Expression[:edx, :&, 4294967295], g.expr[:ecx].reduce
				assert_equal is.size, g.size
		end

		def test_from_str
				g1 = Gadget.from_str('push eax; push esp; ret')
				g2 = Gadget.new [Instr.as("push eax"), Instr.as("push esp"), Instr.as("ret")]

				assert_equal(3, g1.size)

				assert_equal(Gadget, g1.class)
				assert_equal(g1, g2)
				assert_equal(g1 == g2, true)
		end

		def test_expr
			g3 = Gadget.new [Instr.as("xor eax, eax"), Instr.as("and ebx, 0")]
			assert_equal 0, g3.expr[:eax].reduce

			g4 = Gadget.new [Instr.as("xor eax, eax"), Instr.as("and ebx, 0"), Instr.as("ret")]
			assert_equal 0, g4.expr[:ebx].reduce
		end
end


