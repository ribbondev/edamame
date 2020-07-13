
#################
# compiler config

project('xdi', 'c', default_options: [
  'c_std=c18',
  'warning_level=3'
])

optional_gcc_args = [
  '-fstack-protector-strong'
]

cc = meson.get_compiler('c')

foreach arg: optional_gcc_args
  if cc.has_argument(arg)
    add_project_arguments(arg, language: 'c')
  endif
endforeach

##############
# dependencies

libpe = cc.find_library('libpe', dirs: meson.current_source_dir() + '/src/libpe')
m = cc.find_library('m', required: false)

############
# xdi config

exe_entry_point = ['src/xdi.c']

exe_src = [
  'src/disasm/disasm.c'
]

exe_includes = [
  include_directories('src'),
  include_directories('src/libpe/include')
]

##################
# xdi tests config

test_src = [
  'tests/xdi_tests.c'
]

test_includes = [
  include_directories('src'),
  include_directories('tests/libcester')
]

##################
# produce exe/libs

executable(
  'xdi',
  sources: exe_entry_point + exe_src,
  include_directories: exe_includes,
  dependencies: [libpe, m])

executable(
  'xdi_tests',
  sources: exe_src + test_src,
  include_directories: test_includes + exe_includes,
  dependencies: [libpe, m])
