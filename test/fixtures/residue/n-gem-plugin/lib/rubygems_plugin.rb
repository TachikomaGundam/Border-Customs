require "rubygems"

Gem.post_install do |installer|
  spec = installer.spec
  warn "installed #{spec.name}"
end
