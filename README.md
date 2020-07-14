## edamame
Experimental reversing tool for dumping PE files `D2` `libpe` `linux`

## build reqs
- standard C compiler 
- D2 compiler (https://dlang.org/)
- meson: https://mesonbuild.com/
- ninja: https://ninja-build.org/

## optional
- just: https://github.com/casey/just

## dependencies
- [libpe](https://github.com/merces/libpe) (included in src/libpe)

```sh
# prepare submodules & dependencies
just setup
# build with meson/ninja
just build
# run
just run
```

## testing
```sh
# cross compile w64 test applications
cd tests/test_applications
just build-w64
cd ../..

# run tests
just test
```

*(if not using just, build using standard meson workflow)*