SUBDIRS =         src etc t
ACLOCAL_AMFLAGS = -I config
EXTRA_DIST = \
	config/tap-driver.sh \
	NOTICE.LLNS \
	README.md

# coverage
CODE_COVERAGE_IGNORE_PATTERN = \
        "/t/*" \
	"*_test.c" \
	"test/*.c" \
	"libtap/*" \
	"/usr/*"
CODE_COVERAGE_LCOV_OPTIONS =
@CODE_COVERAGE_RULES@
