
setup:
  git submodule init
  git submodule update
  meson builddir
  cd src/libpe && make

build:
  cd builddir && ninja

run:
  cd builddir && ninja
  ./builddir/xdi

test:
  cd builddir && ninja
  ./builddir/xdi_tests
