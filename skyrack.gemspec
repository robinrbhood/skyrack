# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "skyrack/version"

Gem::Specification.new do |s|
  s.name        = "skyrack"
  s.version     = Skyrack::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Jean-Baptiste Aviat"]
  s.email       = ["Jean-Baptiste.Aviat@hsc.fr"]
  s.homepage    = "http://www.hsc.fr/"
  s.summary     = %q{Lists gadgets from binary files.}
  s.description = %q{Lists gadgets from binary files and helps to generate ROP payloads.}

  s.rubyforge_project = "skyrack"

	s.add_dependency("sqlite3")
	s.add_dependency("rgl")

	exclude = %w(samples lib/skyrack/expr.rb todo.txt notes bin/sky_publish hscdemo doc notes pkg)

  s.files         = `git ls-files`.split("\n").select { |f| exclude.select { |e| f.index(e) }.size == 0 }
  puts s.files
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").select { |f| exclude.select { |e| f.index(e) }.size == 0 }.map{ |f| File.basename(f) }

  s.rdoc_options << '--main' << 'lib/skyrack/version.rb'

  s.require_paths = ["lib"]
end

