AM_CFLAGS = \
	$(WARNING_CFLAGS) \
	-Wno-sign-compare -Wno-unused-parameter -Wno-parentheses \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS) \
	$(JANSSON_LIBS) $(SODIUM_LIBS) $(LIBUUID_LIBS)

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(JANSSON_CFLAGS) $(SODIUM_CFLAGS) $(LIBUUID_CFLAGS)

noinst_LTLIBRARIES = \
	libca.la

libca_la_SOURCES = \
	sigcert.c \
	sigcert.h \
	ca.c \
	ca.h

TESTS = \
	test_sigcert.t \
	test_ca.t

test_ldadd = \
	$(top_builddir)/src/libca/libca.la \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtomlc99/libtomlc99.la \
	$(top_builddir)/src/libtap/libtap.la \
	$(JANSSON_LIBS) $(SODIUM_LIBS) $(LIBUUID_LIBS)

test_cppflags = \
	$(AM_CPPFLAGS)

check_PROGRAMS = \
	$(TESTS)

TEST_EXTENSIONS = .t
T_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

test_sigcert_t_SOURCES = test/sigcert.c
test_sigcert_t_LDADD = $(test_ldadd)
test_sigcert_t_CPPFLAGS = $(test_cppflags)

test_ca_t_SOURCES = test/ca.c
test_ca_t_LDADD = $(test_ldadd)
test_ca_t_CPPFLAGS = $(test_cppflags)
