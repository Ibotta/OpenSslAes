#!/usr/bin/env ruby
require './open_ssl_aes'

mode = ARGV[0]
i = ARGV[1]
o = ARGV[2]
pass = ARGV[3]

infile = File.open(i, 'r').binmode
outfile = File.open(o, 'w').binmode

c = OpenSslAes.new(pass)

if mode == 'enc'
  c.encrypt(infile, outfile)
elsif mode == 'dec'
  c.decrypt(infile, outfile)
end
