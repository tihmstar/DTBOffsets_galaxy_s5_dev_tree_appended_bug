AM_CFLAGS = -I$(top_srcdir)/include $(libgeneral_CFLAGS) $(libinsn_CFLAGS) $(libpatchfinder_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libgeneral_LIBS) $(libinsn_LIBS) $(libpatchfinder_LIBS)


bin_PROGRAMS = dtboffsets

dtboffsets_CFLAGS = $(AM_CFLAGS)
dtboffsets_CXXFLAGS = $(AM_CXXFLAGS)
dtboffsets_LDFLAGS = $(AM_LDFLAGS)
dtboffsets_SOURCES = 	main.cpp \
                      DTBOffsets.cpp
