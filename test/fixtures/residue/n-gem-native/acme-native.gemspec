Gem::Specification.new do |s|
  s.name = "acme-native"
  s.version = "0.1.0"
  s.summary = "Confined mkmf extension gem for the R3b residue leg"
  s.authors = ["Acme"]
  s.email = "acme@example.invalid"
  s.homepage = "https://example.invalid/acme-native"
  s.license = "MIT"
  s.files = ["acme-native.gemspec", "ext/ghost/extconf.rb", "lib/acme.rb"]
  s.extensions = ["ext/ghost/extconf.rb"]
  s.require_paths = ["lib"]
end
