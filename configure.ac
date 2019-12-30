AC_INIT([lifesaverc], 1.0, [marioferreira2110@gmail.com])
AC_PROG_CC
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_SEARCH_LIBS([archive_write_new], [archive],
	[ AC_MSG_RESULT([libarchive development package found])],
	[ AC_MSG_ERROR([libarchive development package not found])
])
AC_SEARCH_LIBS([ssh_new], [ssh],
	[ AC_MSG_RESULT([libssh development package found])],
	[ AC_MSG_ERROR([libssh development package not found])
])


AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
