= Skyrack

Premier sur le rop.

== Installation

Skyrack should sucessfully run on any platform supporting Ruby and has been
tested under Linux, Mac OS, Windows (but not by me ;).

Be sure to have ruby and the gem utility (sometimes packaged as rubygems).

    $ gem install skyrack_file.gem

Dependencies will automatically be fetched and installed if you have an internet
access.

If you have trouble installing sqlite3, you may want to add the sqlite3 headers
to your system:

Debian-like:
   $ sudo aptitude install libsqlite3-dev
Fedora:
   $ yum install sqlite3-devel'


You also need metasm:
    $ hg clone https://metasm.googlecode.com/hg/ metasm 

You'll then need yo set your Ruby path points to Metasm directory:
    $ export RUBYLIB=$RUBYLIB:/path/to/metasm

== Documentation

Options can be seen by passing the '-h' or '--help' flag to each executable
file.

== Examples

=== sky_build_db
Builds the gadget db of a binary file.

Example:
    $ sky_build_db /path/to/libeay32.dll

=== sky_search
Search a gadget db built with +sky_build_db+:: for specific instructions.

Examples:
    $ sky_search -f db/libeay32.dll.sqlite3 -a 'mov eax' -s ebp+

    $ sky_search -f db/libeay32.dll.sqlite3 -a 'mov [eax]' -l -1 --preserve-eip+

Interesting patterns found by sky_search should be redirected to a file :

    $ sky_search -f db.sqlite3 -a 'xor ebx, ebx' -l 1 > result.txt

Consecutive instructions may be searched by adding the -a expression multiple
times:

    $ sky_search -f db.sqlite3 -a 'mov eax, [ebp+8]' -a 'jmp eax' > result.txt

Which will return the following instruction sequence:

   mov eax, [ebp+8]
   jmp eax


=== sky_search_raw
Search a binary file for specific instructions. Assembled on the fly.
    $ sky_search_raw -i "jmp eax" /path/to/libeay32.dll
    $ sky_search_raw --all -i 'call [eax+4]' /path/to/libeay32.dll

=== sky_generate

Converts the human readable payload into a binary file:
		$ sky_generate -f ..sqlite3 result.txt > payload.bin

An offset may also be given (should correspond to the load address of the
exploited library):
		$ sky_generate -f ..sqlite3 -o 0x7ffff4b00 result.txt > payload.bin

=== sky_convert

Converts an exploit generated for a library to an exploit working with an other
library. Eg you have a working exploit.txt generated with libssl0.9.8c, you can
convert it to libssl0.9.8d:
    $ sky_convert exploit.txt libssl0.9.8d.sqlite3 > exploit_new.txt

If you are lucky, you may even be able to convert it to a different library
gadgets database.

You need to generate libssl0.9.8d gadget database in order to provide it to
sky_convert:

    $ sky_build_db libssl0.9.8d

== Troubles

If you can't find sky_* in your path, you may access it directly this way:

    $ gem which skyrack
    /.../gems/ree-1.8.7-head/gems/skyrack-0.1.2.1/lib/skyrack.rb

bin/ directory is at the same level as lib/:

    $ /.../gems/ree-1.8.7-head/gems/skyrack-0.1.2.1/bin/sky_build_db

== Links

Skyrack is written by Jean-Baptiste Aviat, an HSC consultant.
http://www.hsc.fr

Metasm: http://metasm.cr0.org/


== Changelog

=== v0.1.2
        * new generation method, now 10 times faster
        * database opening bug corrected

=== v0.1.2.1
        * sky_convert works better and faster
        * sky_convert does not need any more the original gadet database, only
          the destination one
        * bigfux: sky_generate did not work with using Ruby 1.8 
        * database is now looked for in current directory

