/*
 *  Vimterrier - GTK+ based simple text editor
 *  Copyright (C) 2004-2005 Tarot Osuji
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <glib/gprintf.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include "blowfish.h"
// Brad Conte's implementation: github.com/B-Con/crypto-algorithms/blob/master/blowfish.c
#include "vimterrier.h"

#define SALT_SIZE 8
#define KEY_SIZE 32
#define VERSION_SIZE 12

gchar *password;

/* It reads two big-endian 32-bit words and writes them back as little-endian
   32-bit words (8 bytes total). */
static void swapendian8(const unsigned char in[8], unsigned char out[8]) {
    uint32_t a, b;

    memcpy(&a, in,     sizeof(a));
    memcpy(&b, in + 4, sizeof(b));

    a = __builtin_bswap32(a);
    b = __builtin_bswap32(b);

    memcpy(out,     &a, sizeof(a));
    memcpy(out + 4, &b, sizeof(b));
}

/* wrapper: encrypt one 8-byte block using Blowfish and swapendian in/out transformation */
static void bf_encrypt_block_swap(const BLOWFISH_KEY *bfkey, const unsigned char in[8], unsigned char out[8]) {
    unsigned char tmp_in[8], tmp_out[8], swapped_out[8];
    swapendian8(in, tmp_in);
    blowfish_encrypt(tmp_in, tmp_out, bfkey);
    swapendian8(tmp_out, swapped_out);
    memcpy(out, swapped_out, 8);
}

gboolean check_file_writable(gchar *filename)
{
	FILE *fp;

	if ((fp = fopen(filename, "a")) != NULL) {
		fclose(fp);
		return TRUE;
	}
	return FALSE;
}

gchar *get_file_basename(gchar *filename, gboolean bracket)
{
	gchar *basename = NULL;
	gchar *tmp;
	gboolean exist_flag;

	if (filename) {
		tmp = g_path_get_basename(
			g_filename_to_utf8(filename, -1, NULL, NULL, NULL));
		exist_flag = g_file_test(
			g_filename_to_utf8(filename, -1, NULL, NULL, NULL),
			G_FILE_TEST_EXISTS);
	} else {
		tmp = g_strdup(_("Untitled"));
		exist_flag = FALSE;
	}

	if (bracket) {
		if (!exist_flag) {
			GString *string = g_string_new(tmp);
			g_string_prepend(string, "(");
			g_string_append(string, ")");
			basename = g_strdup(string->str);
			g_string_free(string, TRUE);
		} else if (!check_file_writable(filename)) {
			GString *string = g_string_new(tmp);
			g_string_prepend(string, "<");
			g_string_append(string, ">");
			basename = g_strdup(string->str);
			g_string_free(string, TRUE);
		}
	}

	if (!basename)
		basename = g_strdup(tmp);
	g_free(tmp);

	return basename;
}

gchar *parse_file_uri(gchar *uri)
{
	gchar *filename;
//	gchar **strs;

	if (g_strstr_len(uri, 5, "file:"))
		filename = g_filename_from_uri(uri, NULL, NULL);
	else {
		if (g_path_is_absolute(uri))
			filename = g_strdup(uri);
		else
			filename = g_build_filename(g_get_current_dir(), uri, NULL);
	}
/*	if (strstr(filename, " ")) {
		strs = g_strsplit(filename, " ", -1);
		g_free(filename);
		filename = g_strjoinv("\\ ", strs);
		g_strfreev(strs);
	}
*/
	return filename;
}

gint file_open_real(GtkWidget *view, FileInfo *fi)
{
	gchar *contents;
	gsize length;
	GError *err = NULL;
	const gchar *charset;
	gchar *str = NULL;
	GtkTextIter iter;
	guchar salt[SALT_SIZE];
	guchar version[VERSION_SIZE];

	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));

	if (!g_file_get_contents(fi->filename, &contents, &length, &err)) {
		if (g_file_test(fi->filename, G_FILE_TEST_EXISTS)) {
			run_dialog_message(gtk_widget_get_toplevel(view),
				GTK_MESSAGE_ERROR, err->message);
			g_error_free(err);
			return -1;
		}
		g_error_free(err);
		err = NULL;
		contents = g_strdup("");
	}

	memcpy(version, contents, VERSION_SIZE);
	memcpy(salt, contents + VERSION_SIZE, SALT_SIZE);

	if (memcmp(version, "VimCrypt~03!", 12) != 0) {
		run_dialog_message(gtk_widget_get_toplevel(view),
			GTK_MESSAGE_ERROR, _("Error: Unsupported format version"));
		return -1;
	}

	password = get_user_input();

	if (password == NULL || strcmp(password, "") == 0) goto skipdec;

	unsigned char key[KEY_SIZE];
    char pw_hex[65];
	size_t pwlen = strlen(password);

    memcpy(pw_hex, password, pwlen);
    pw_hex[pwlen] = '\0';

	/* Key derivation */
    for (int i = 0; i < 1001; i++) {
        unsigned char tmp[pwlen + 8];

        memcpy(tmp, pw_hex, pwlen);
        memcpy(tmp + pwlen, salt, 8);

        crypto_hash_sha256(key, tmp, pwlen + 8);
        sodium_bin2hex(pw_hex, 65, key, 32);
        pwlen = 64; // always 64 hex chars after first hash
    }

    /* Initialize Blowfish key structure */
    BLOWFISH_KEY bfkey;
    blowfish_key_setup(key, &bfkey, 32);
    sodium_memzero(key, 32);

	unsigned char block0[8];
	memcpy(block0, contents + VERSION_SIZE + SALT_SIZE, 8);

	unsigned char *decrypted = NULL;
	size_t output_size = 0;
	size_t offset = VERSION_SIZE + SALT_SIZE + 8;
	/* Decryption loop */
	while (1) {
		size_t remaining = length - offset;
		size_t r = remaining >= 8 ? 8 : remaining;

		unsigned char cipher_of_block0[8];
		bf_encrypt_block_swap(&bfkey, block0, cipher_of_block0);

		unsigned char *new_output = realloc(decrypted, output_size + r);
		if (!new_output) {
			printf("Error: realloc\n");
			free(decrypted);
			return 1;
		}
		decrypted = new_output;

		for (size_t i = 0; i < r; ++i)
			decrypted[output_size + i] = cipher_of_block0[i] ^ contents[offset + i];

		output_size += r;

		if (r != 8) {
			decrypted[output_size] = '\0'; // null-terminate string
			break;
		}

		memcpy(block0, &contents[offset], 8);
		offset += 8;
	}

	gchar *contentdec = (gchar *)decrypted;

	fi->lineend = detect_line_ending(contentdec);
	if (fi->lineend != LF)
		convert_line_ending_to_lf(contentdec);

	if (fi->charset)
		charset = fi->charset;
	else {
		charset = detect_charset(contentdec);
		if (charset == NULL)
			charset = get_default_charset();
	}

	if (length)
		do {
			if (err) {
				charset = "ISO-8859-1";
				g_error_free(err);
				err = NULL;
			}
			str = g_convert(contentdec, -1, "UTF-8", charset, NULL, NULL, &err);
		} while (err);
	else
		str = g_strdup("");
	g_free(contents);

	if (charset != fi->charset) {
		g_free(fi->charset);
		fi->charset = g_strdup(charset);
		if (fi->charset_flag)
			fi->charset_flag = FALSE;
	}

	//g_free(decrypted);

//	undo_disconnect_signal(textbuffer);
//	undo_block_signal(buffer);
	force_block_cb_modified_changed(view);

	gtk_text_buffer_set_text(buffer, "", 0);
	gtk_text_buffer_get_start_iter(buffer, &iter);
	gtk_text_buffer_insert(buffer, &iter, str, strlen(str));
	gtk_text_buffer_get_start_iter(buffer, &iter);
	gtk_text_buffer_place_cursor(buffer, &iter);
	gtk_text_buffer_set_modified(buffer, FALSE);
	gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(view), &iter, 0, FALSE, 0, 0);
	g_free(str);

	force_unblock_cb_modified_changed(view);
	menu_sensitivity_from_modified_flag(FALSE);
//	undo_unblock_signal(buffer);

	skipdec:

	return 0;
}

gint file_save_real(GtkWidget *view, FileInfo *fi)
{
	FILE *fp;
	GtkTextIter start, end;
	gchar *str, *cstr;
	gsize rbytes, wbytes;
	GError *err = NULL;
	guchar salt[SALT_SIZE];
	guchar key[KEY_SIZE];

	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));

	gtk_text_buffer_get_start_iter(buffer, &start);
	gtk_text_buffer_get_end_iter(buffer, &end);
	str = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);

	switch (fi->lineend) {
	case CR:
		convert_line_ending(&str, CR);
		break;
	case CR+LF:
		convert_line_ending(&str, CR+LF);
	}

	if (!fi->charset)
		fi->charset = g_strdup(get_default_charset());
	cstr = g_convert(str, -1, fi->charset, "UTF-8", &rbytes, &wbytes, &err);
	g_free(str);
	if (err) {
		switch (err->code) {
		case G_CONVERT_ERROR_ILLEGAL_SEQUENCE:
			run_dialog_message(gtk_widget_get_toplevel(view),
				GTK_MESSAGE_ERROR, _("Can't convert codeset to '%s'"), fi->charset);
			break;
		default:
			run_dialog_message(gtk_widget_get_toplevel(view),
				GTK_MESSAGE_ERROR, err->message);
		}
		g_error_free(err);
		return -1;
	}

	if (password == NULL) {
		password = get_user_input();
	}

	if (strcmp(password, "") != 0) {
		const guchar version[] = "VimCrypt~03!";
		randombytes_buf(salt, sizeof salt);

		char pw_hex[65];
		size_t pwlen = strlen(password);

		memcpy(pw_hex, password, pwlen);
		pw_hex[pwlen] = '\0';

		for (int i = 0; i < 1001; i++) {
			unsigned char tmp[pwlen + 8];

			memcpy(tmp, pw_hex, pwlen);
			memcpy(tmp + pwlen, salt, 8);

			crypto_hash_sha256(key, tmp, pwlen + 8);
			sodium_bin2hex(pw_hex, 65, key, 32);
			pwlen = 64;
		}

		BLOWFISH_KEY bfkey;
		blowfish_key_setup(key, &bfkey, 32);
		sodium_memzero(key, 32);

		unsigned char block0[8];
		randombytes_buf(block0, 8);
		unsigned char firstblock[8];
		memcpy(firstblock, block0, 8);

		size_t plaintext_len = strlen(cstr);

		unsigned char plain[8];
		unsigned char cipher_of_block0[8], cipher_block[8];
		unsigned char *out_data = malloc(plaintext_len + 7);
		size_t total_written = 0;
		size_t offset = 0;
		/* Encryption loop */
		while (offset < plaintext_len) {
			size_t r = plaintext_len - offset;
			if (r > 8) r = 8;

			memcpy(plain, cstr + offset, r);

			bf_encrypt_block_swap(&bfkey, block0, cipher_of_block0);

			for (int i = 0; i < r; ++i)
				cipher_block[i] = cipher_of_block0[i] ^ plain[i];

			memcpy(out_data + total_written, cipher_block, r);
			total_written += r;

			memcpy(block0, cipher_block, r);

			if (r < 8) break;

			offset += r;
		}

		size_t total_len = VERSION_SIZE + SALT_SIZE + 8 + plaintext_len;

		guchar *cstr_encrypted = malloc(total_len);

		memcpy(cstr_encrypted, &version, VERSION_SIZE);
		memcpy(cstr_encrypted + VERSION_SIZE, salt, SALT_SIZE);
		memcpy(cstr_encrypted + VERSION_SIZE + SALT_SIZE, firstblock, 8);
		memcpy(cstr_encrypted + VERSION_SIZE + SALT_SIZE + 8, out_data, total_written);

		fp = fopen(fi->filename, "w");
		if (!fp) {
			run_dialog_message(gtk_widget_get_toplevel(view),
				GTK_MESSAGE_ERROR, _("Can't open file to write"));
			return -1;
		}
		if (fwrite(cstr_encrypted, 1, total_len, fp) != total_len) {
			run_dialog_message(gtk_widget_get_toplevel(view),
				GTK_MESSAGE_ERROR, _("Can't write file"));
			fclose(fp);
			return -1;
		}

		gtk_text_buffer_set_modified(buffer, FALSE);
		fclose(fp);
		g_free(cstr);
		g_free(cstr_encrypted);
	}

	return 0;
}

#if ENABLE_STATISTICS
void text_stats(gchar * text, gint * wc, gint * lc);
gint skipDelim(gchar ** pos);
gboolean isDelim(gchar);

gchar * file_stats(GtkWidget *view, FileInfo *fi)
{
	GtkTextIter start;
	GtkTextIter end;
	GtkTextIter textStart;
	GtkTextIter textEnd;
	gchar * str;
	gchar * text;
	gint totalLines = 0;
	gint totalChars = 0;
	gint totalWords = 0;
	gint charCount  = 0;
	gint wordCount  = 0;
	gint lineCount  = 0;
	gchar * toret = g_malloc( 8192 );
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
	gboolean hasSelection = gtk_text_buffer_get_selection_bounds( buffer, &start, &end );

	if ( !hasSelection ) {
		gtk_text_buffer_get_start_iter(buffer, &start);
		gtk_text_buffer_get_start_iter(buffer, &end);
	}

	gtk_text_buffer_get_start_iter(buffer, &textStart);
	gtk_text_buffer_get_end_iter(buffer, &textEnd);

	str  = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
	text = gtk_text_buffer_get_text(buffer, &textStart, &textEnd, FALSE);

	totalChars = gtk_text_buffer_get_char_count( buffer );
	charCount  = strlen( str );

	text_stats( str, &wordCount, &lineCount );
	text_stats( text, &totalWords, &totalLines );

	g_sprintf(
		toret,
		_("<u>Totals count</u>\nChars: %7d Words: %6d Lines: %5d\n\n"
		"<u>Selection</u>\nChars: %7d Words: %6d Lines: %5d\n"),
		totalChars,
		totalWords,
		totalLines,
		charCount,
		wordCount,
		lineCount
	);

	return toret;
}

const gchar * DelimChars = " ,.;:\t\n-_?¿()!¡'/&%$#\"\\|{}[]+*";

void text_stats(gchar * text, gint * wc, gint * lc)
{
	gchar * pos = text;
	*wc = 0;
	*lc = 1;

	*lc += skipDelim( &pos );
	while( *pos != 0 ) {
		++(*wc);
		while( *pos != 0
		    && !isDelim( *pos ) )
		{
			++pos;
		}

		*lc += skipDelim( &pos );
	}
}

gint skipDelim(gchar ** pos)
{
	gint lc = 0;

	while( **pos != 0
            && isDelim( **pos ) )
	{
		if ( **pos == '\n' ) {
			++lc;
		}
		++( *pos );
	}

	return lc;
}

inline
gboolean isDelim(gchar ch)
{
	return ( strchr( DelimChars, ch ) != NULL );
}
#endif
