require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake/testtask'

Rake::TestTask.new do |t|
		t.libs << "test"
		t.test_files = FileList['test/test*.rb']
		t.verbose = true
end

task :onfile_rdoc do
end

desc "Publish Skyrack to HSC website"
task :publish => [:build] do
		targets = []
		targets << Dir[File.join('pkg', '*.gem')].sort.last
		targets << 'README'
		`./bin/sky_publish #{targets.join(' ')}`.each_line {|l| puts l}
end
