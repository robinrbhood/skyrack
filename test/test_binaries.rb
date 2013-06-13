#!/usr/bin/env ruby

begin
		require 'skyrack/roper'
		require 'skyrack/gadget_db'
rescue LoadError
		require 'rubygems'
		require 'skyrack/roper'
		require 'skyrack/gadget_db'
end

require 'fileutils'

require 'rubygems'
require 'rgl/dot'

require 'tempfile'

require 'test/unit'

TEST_FOLDER = File.join(File.dirname(__FILE__), "binaries", "**", "*")


def puts_infos(m)
    puts m.header.type if m.is_a? Metasm::ELF
    puts m.header.machine
    puts m.cpu.class
    Instr.cpu = m.cpu
    puts "image base addr: 0x%x" % m.base_addr if m.is_a? Metasm::COFF
    m.sky_each_section do |s, s_addr|
        puts "%s - executable: %s" % [s.to_s, s.executable?]
				RopSection::RETS.each do |hex, info|
						puts "\t%d ret (%x)" % [s.get_addr_of(hex).size, hex]
				end
       s.get_rets().each do |ret, indexes|
           puts "%s\t%d" % [ret, indexes.size]
       end
    end
    exit(0)
end

def test_infos(filename, macho_type = nil)
    test(filename, macho_type, true)
end

def test(filename, macho_type=nil, infos = false)

    db_file = Tempfile.new("skyrack_bin_tests").path
    File.unlink(db_file)

    opt = {
        :start_addr => nil, 
        :filename => filename,
        :depth => 5,
        :save => db_file,
        :infos => infos
    }

    m = Metasm::AutoExe.decode_file(opt[:filename])

    if m.class == Metasm::MachO then
        m = Metasm::UniversalBinary.decode_file(opt[:filename])
        choice = nil
        m.archive.each_with_index do |ar, idx|
            if ar.cputype.to_s.downcase.index(macho_type.downcase)
                choice = idx
                break
            end
        end
        if not choice
            puts "error: macho type %s not found for %s" % [macho_type, filename]
            return false
        end
        m = m[choice]
    end

    if opt[:info]
        puts_infos(m) 
        exit 0
    end

    db = GadgetDb.new(db_file, m)
    puts "saving results in %s" % db_file


    m.each_gadget_graph(3) do |gadget, addr|
        db.save_gadget(gadget)
    end

    db.close

    File.unlink(db_file)

    return true
end


class TestBinaryFiles < Test::Unit::TestCase

    def each_bin_file(directory)
        for filename in Dir[directory] do
            next unless File.file? filename
            puts "processing %s" % filename
            if filename.index('macho') then
                for arch in %w(x86_64 i386) do
                    yield(filename, arch)
                end
            else
                yield(filename, arch)
            end
        end

    end

    def test_build_db_all_archs
        each_bin_file(TEST_FOLDER) do |file, arch|
                assert test(file, arch)
        end
    end

    def test_infos_all_archs
        each_bin_file(TEST_FOLDER) do |file, arch|
                assert test_infos(file, arch)
        end
    end

end
