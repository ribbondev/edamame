
project('edamame', 'c', 'd',
  default_options: ['c_std=c18'])

######
# libs

cc = meson.get_compiler('c')
libpe = cc.find_library('libpe', dirs: meson.current_source_dir() + '/src/libpe')
m = cc.find_library('m', required: false)

#########
# sources

exe_entry_point = ['src/edamame.d']
exe_sources = ['src/pe.d']
source_directories = ['src']

##############
# executables

executable('edamame',
  sources: exe_entry_point + exe_sources,
  include_directories: source_directories,
  dependencies: [libpe, m])
