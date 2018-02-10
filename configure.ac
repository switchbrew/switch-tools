#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([switch-tools],[1.1.1],[https://github.com/switchbrew/switch-tools/issues])
AC_CONFIG_SRCDIR([src/build_pfs0.c])

AM_INIT_AUTOMAKE([subdir-objects])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

AC_PROG_CC


PKG_CHECK_MODULES([LZ4],
		[liblz4 >= 1.7.1 liblz4 < 100],
		[have_lz4="yes"],
		[PKG_CHECK_MODULES([LZ4],
			[liblz4 >= 131],
			[have_lz4="yes"])
])

AC_SUBST(LZ4_LIBS)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
