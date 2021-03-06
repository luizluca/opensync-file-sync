/*
 * opensync - A plugin for file objects for the opensync framework
 * Copyright (C) 2004-2005  Armin Bauer <armin.bauer@opensync.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <string.h>
#include <glib.h>

#include <opensync/opensync.h>
#include <opensync/opensync-common.h>
#include <opensync/opensync-format.h>

#include "file.h"

static OSyncConvCmpResult compare_file(const char *leftdata, unsigned int leftsize, const char *rightdata, unsigned int rightsize, void *user_data, OSyncError **error)
{
	OSyncFileFormat *leftfile = (OSyncFileFormat *)leftdata;
	OSyncFileFormat *rightfile = (OSyncFileFormat *)rightdata;

	osync_trace(TRACE_ENTRY, "%s(%p, %i, %p, %i)", __func__, leftdata, leftsize, rightdata, rightsize);
	osync_assert(leftdata);
	osync_assert(rightdata);

	osync_assert(rightfile->path);
	osync_assert(leftfile->path);

	osync_trace(TRACE_INTERNAL, "Comparing %s and %s", leftfile->path, rightfile->path);


	if (!strcmp(leftfile->path, rightfile->path)) {
		if (leftfile->size == rightfile->size) {
			if (leftfile->size == 0 || !memcmp(leftfile->data, rightfile->data, rightfile->size)) {
				osync_trace(TRACE_EXIT, "%s: Same", __func__);
				return OSYNC_CONV_DATA_SAME;
			}
		}

		osync_trace(TRACE_EXIT, "%s: Similar", __func__);
		return OSYNC_CONV_DATA_SIMILAR;
	}

	osync_trace(TRACE_EXIT, "%s: Mismatch", __func__);
	return OSYNC_CONV_DATA_MISMATCH;
}

static osync_bool conv_file_to_plain(char *input, unsigned int inpsize, char **output, unsigned int *outpsize, osync_bool *free_input, const char *config, void *user_data, OSyncError **error)
{
	OSyncFileFormat *file = (OSyncFileFormat *)input;
	char *plaindata = NULL;
	osync_trace(TRACE_INTERNAL, "Converting file to plain");

	*free_input = TRUE;

	/* Add a \0 to make a usable plain (text) format. input gets freed by destroy_func() */
	plaindata = osync_try_malloc0(file->size + 1, error);
	memcpy(plaindata, file->data, file->size);

	*output = plaindata;
	*outpsize = file->size + 1;

	return TRUE;
}

static osync_bool conv_plain_to_file(char *input, unsigned int inpsize, char **output, unsigned int *outpsize, osync_bool *free_input, const char *config, void *userdata, OSyncError **error)
{
	OSyncFileFormat *file = NULL;
	osync_trace(TRACE_INTERNAL, "Converting plain to file");

	*free_input = FALSE;
	file = osync_try_malloc0(sizeof(OSyncFileFormat), error);
	if (!file)
		goto error;

	file->path = osync_rand_str(100, error);
	if (!file->path)
		goto error;

	file->data = input;
	file->size = inpsize - 1;

	*output = (char *)file;
	*outpsize = sizeof(OSyncFileFormat);
	return TRUE;

error:
	return FALSE;
}

static osync_bool destroy_file(char *input, unsigned int inpsize, void *user_data, OSyncError **error)
{
	OSyncFileFormat *file = (OSyncFileFormat *)input;

	if (file->data)
		g_free(file->data);

	if (file->path)
		g_free(file->path);

	g_free(file);

	return TRUE;
}

static osync_bool duplicate_file(const char *uid, const char *input, unsigned int insize, char **newuid, char **output, unsigned int *outsize, osync_bool *dirty, void *user_data, OSyncError **error)
{
	OSyncFileFormat *file = (OSyncFileFormat *)input;

	char *newpath = g_strdup_printf ("%s-dupe", file->path);
	g_free(file->path);
	file->path = newpath;
	*newuid = g_strdup(file->path);
	*dirty = TRUE;
	return TRUE;
}

static osync_bool copy_file(const char *input, unsigned int inpsize, char **output, unsigned int *outpsize, void *user_data, OSyncError **error)
{
	OSyncFileFormat *inpfile = (OSyncFileFormat *)input;

	OSyncFileFormat *outfile = osync_try_malloc0(sizeof(OSyncFileFormat), error);
	if (!outfile)
		return FALSE;

	if (inpfile->data) {
		outfile->data = g_malloc0(inpfile->size);
		memcpy(outfile->data, inpfile->data, inpfile->size);
		outfile->size = inpfile->size;
	}

	outfile->path = g_strdup(inpfile->path);

	*output = (char *)outfile;
	*outpsize = sizeof(OSyncFileFormat);
	return TRUE;
}

static time_t revision_file(const char *input, unsigned int inpsize, void *user_data, OSyncError **error)
{
	OSyncFileFormat *file = (OSyncFileFormat *)input;
	time_t lastmod;

	osync_trace(TRACE_ENTRY, "%s(%p, %i, %p)", __func__, input, inpsize, error);

	lastmod = file->last_mod;

	osync_trace(TRACE_EXIT, "%s: %li", __func__, lastmod);
	return lastmod;
}

static char *print_file(const char *data, unsigned int size, void *user_data, OSyncError **error)
{
	OSyncFileFormat *file = (OSyncFileFormat *)data;

	char *printable = osync_strdup_printf ("File %s: size: %i", file->path, file->size);
	return printable;
}

static osync_bool marshal_file(const char *input, unsigned int inpsize, OSyncMarshal *marshal, void *user_data, OSyncError **error)
{
	OSyncFileFormat *file = (OSyncFileFormat *)input;
	osync_trace(TRACE_ENTRY, "%s(%p, %i, %p, %p)", __func__, input, inpsize, marshal, error);

	if (!osync_marshal_write_string(marshal, file->path, error))
		goto error;

	if (!osync_marshal_write_buffer(marshal, file->data, file->size, error))
		goto error;

	osync_trace(TRACE_EXIT, "%s", __func__);
	return TRUE;

error:
	osync_trace(TRACE_EXIT_ERROR, "%s: %s", __func__, osync_error_print(error));
	return FALSE;

}

static osync_bool demarshal_file(OSyncMarshal *marshal, char **output, unsigned int *outpsize, void *user_data, OSyncError **error)
{
	OSyncFileFormat *file = NULL;
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p)", __func__, marshal, output, outpsize, error);

	file = osync_try_malloc0(sizeof(OSyncFileFormat), error);
	if (!file)
		goto error;

	if (!osync_marshal_read_string(marshal, &(file->path), error))
		goto error;

	if (!osync_marshal_read_buffer(marshal, (void *)&(file->data), &(file->size), error))
		goto error;

	*output = (char *)file;
	*outpsize = sizeof(OSyncFileFormat);

	osync_trace(TRACE_EXIT, "%s", __func__);
	return TRUE;

error:

	osync_trace(TRACE_EXIT_ERROR, "%s: %s", __func__, osync_error_print(error));
	return FALSE;
}

osync_bool get_format_info(OSyncFormatEnv *env, OSyncError **error)
{
	OSyncObjFormat *format = osync_objformat_new("file", "data", error);
	if (!format)
		goto error;

	osync_objformat_set_compare_func(format, compare_file);
	osync_objformat_set_destroy_func(format, destroy_file);
	osync_objformat_set_duplicate_func(format, duplicate_file);
	osync_objformat_set_print_func(format, print_file);
	osync_objformat_set_revision_func(format, revision_file);
	osync_objformat_set_copy_func(format, copy_file);

	osync_objformat_set_marshal_func(format, marshal_file);
	osync_objformat_set_demarshal_func(format, demarshal_file);

	if (!osync_format_env_register_objformat(env, format, error))
		goto error;

	osync_objformat_unref(format);
	return TRUE;

error:
	return FALSE;
}

osync_bool get_conversion_info(OSyncFormatEnv *env, OSyncError **error)
{
	OSyncObjFormat *file = osync_format_env_find_objformat(env, "file");
	OSyncObjFormat *plain = NULL;
	OSyncFormatConverter *conv = NULL;

	if (!file) {
		osync_error_set(error, OSYNC_ERROR_GENERIC, "Unable to find file format");
		return FALSE;
	}

	plain = osync_format_env_find_objformat(env, "plain");
	if (!plain) {
		osync_error_set(error, OSYNC_ERROR_GENERIC, "Unable to find plain format");
		return FALSE;
	}

	conv = osync_converter_new(OSYNC_CONVERTER_DECAP, file, plain, conv_file_to_plain, error);
	if (!conv)
		return FALSE;

	osync_format_env_register_converter(env, conv, error);
	osync_converter_unref(conv);

	conv = osync_converter_new(OSYNC_CONVERTER_ENCAP, plain, file, conv_plain_to_file, error);
	if (!conv)
		return FALSE;

	osync_format_env_register_converter(env, conv, error);
	osync_converter_unref(conv);
	return TRUE;
}

int get_version(void)
{
	return 1;
}
