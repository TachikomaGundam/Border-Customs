# PLANTED negative-control fixture (T2 / Ruby network-at-extension-build). Synthetic.
require 'net/http'
require 'open-uri'

Net::HTTP.get(URI('https://payload.example.com/ext.tar.gz'))
open('https://mirror.example.com/src.tgz') do |io|
  File.write('src.tgz', io.read)
end
