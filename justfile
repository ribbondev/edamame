
setup:
  git submodule init
  git submodule update
  meson builddir
  cd src/libpe && make

build:
  cd builddir && ninja

run:
  cd builddir && ninja
  ./builddir/edamame

test:
  cd builddir && ninja
  ./builddir/edamame_tests
