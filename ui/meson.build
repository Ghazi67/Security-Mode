project('ui', 'vala', 'c',
  version: '0.1.0',
  meson_version: '>= 0.50.0',
)

gnome = import('gnome')

dependencies = [
  dependency('gio-2.0'),
  dependency('gtk+-3.0'),
  dependency('json-glib-1.0'),
]

sources = [
  'src/main.vala',
  'src/window.vala',
]

executable('ui', sources,
  dependencies: dependencies,
  install: false,
)
