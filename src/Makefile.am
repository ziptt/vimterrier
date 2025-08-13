bin_PROGRAMS = vimterrier

AM_CPPFLAGS = -DICONDIR=\"$(datadir)/pixmaps\"

vimterrier_SOURCES = \
	vimterrier.h main.c \
	blowfish.h blowfish.c \
	window.h window.c \
	menu.h menu.c \
	callback.h callback.c \
	view.h view.c \
	undo.h undo.c \
	font.h font.c \
	linenum.h linenum.c \
	indent.h indent.c \
	hlight.h hlight.c \
	selector.h selector.c \
	file.h file.c \
	encoding.h encoding.c \
	search.h search.c \
	dialog.h dialog.c \
	gtkprint.h gtkprint.c \
	dnd.h dnd.c \
	utils.h utils.c \
	emacs.h emacs.c \
	gtksourceiter.h gtksourceiter.c

vimterrier_CFLAGS  = $(GTK_CFLAGS)
vimterrier_LDADD   = $(GTK_LIBS) $(INTLLIBS) -lsodium
