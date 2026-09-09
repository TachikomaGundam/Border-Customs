require "mkmf"

dir_config("ghost", "/usr")
have_header("ghost.h")
have_library("ghost", "ghost_run")

File.write("acme_ghost.h", "#define ACME_GHOST 1\n")
create_makefile("acme/ghost")
