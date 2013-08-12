{
  'variables': {
    'node_addon': '<!(node -p -e "require(\'path\').dirname(require.resolve(\'addon-layer\'))")',
  },
  'targets': [
    {
      'target_name': 'libdtrace',
      'cflags_cc': ['-fexceptions'],
      'ldflags': ['-ldtrace'],
      'dependencies': [ '<(node_addon)/binding.gyp:addon-layer', ],
      'include_dirs': [ '<(node_addon)/include', ],
      'sources': [ 
        'libdtrace.c'
      ], 
      'libraries': ['-ldtrace'],
      'xcode_settings': {
          'OTHER_CPLUSPLUSFLAGS': [
              '-fexceptions',
              '-Wunused-variable',
          ],
      }
    },
  ]
}
