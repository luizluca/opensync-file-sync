/*
 * file-sync - A plugin for the opensync framework
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

#include "file_sync.h"
#include <opensync/file.h>
#include <opensync/opensync-version.h>
#include <assert.h>
#include <stdlib.h>

static void free_dir(OSyncFileDir *dir)
{
	if (dir->sink)
		osync_objtype_sink_unref(dir->sink);

	if (dir->hashtable)
		osync_hashtable_unref(dir->hashtable);

	g_free(dir);
}

static void free_env(OSyncFileEnv *env)
{
	while (env->directories) {
		OSyncFileDir *dir = env->directories->data;

		free_dir(dir);

		env->directories = g_list_remove(env->directories, dir);
	}
	
	g_free(env);
}

static char *osync_filesync_generate_hash(struct stat *buf)
{
	char *hash = g_strdup_printf("%i-%i", (int)buf->st_mtime, (int)buf->st_ctime);
	return hash;
}

//typedef void (* OSyncSinkWriteFn) 
//typedef void (* OSyncSinkCommittedAllFn) (void *data, OSyncPluginInfo *info, OSyncContext *ctx);


static osync_bool osync_filesync_read(void *userdata, OSyncPluginInfo *info, OSyncContext *ctx, OSyncChange *change)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p)", __func__, userdata, info, ctx, change);
	OSyncObjTypeSink *sink = osync_plugin_info_get_sink(info);
	OSyncFileDir *dir = osync_objtype_sink_get_userdata(sink);
	OSyncFormatEnv *formatenv = osync_plugin_info_get_format_env(info);
	OSyncError *error = NULL;
	
	char *filename = g_strdup_printf("%s/%s", dir->path, osync_change_get_uid(change));
	
	char *data;
	unsigned int size;

	if (!osync_file_read(filename, &data, &size, &error)) {
		osync_change_unref(change);
		osync_context_report_osyncwarning(ctx, error);
		osync_error_unref(&error);
		goto error;
	}

	OSyncData *odata = NULL;

	OSyncFileFormat *file = osync_try_malloc0(sizeof(OSyncFileFormat), &error);
	if (!file) {
		osync_change_unref(change);
		osync_context_report_osyncwarning(ctx, error);
		osync_error_unref(&error);
		goto error_free_data;
	}

	
	struct stat filestats;
	stat(filename, &filestats);
	file->userid = filestats.st_uid;
	file->groupid = filestats.st_gid;
	file->mode = filestats.st_mode;
	file->last_mod = filestats.st_mtime;

	file->data = data;
	file->size = size;
	file->path = g_strdup(osync_change_get_uid(change));
	
	OSyncObjFormat *fileformat = osync_format_env_find_objformat(formatenv, "file");

	odata = osync_data_new((char *)file, sizeof(OSyncFileFormat), fileformat, &error);
	if (!odata) {
		osync_change_unref(change);
		osync_context_report_osyncwarning(ctx, error);
		osync_error_unref(&error);
		g_free(file->path);
		g_free(file);
		goto error_free_data;
	}

	osync_data_set_objtype(odata, osync_objtype_sink_get_name(sink));
	osync_change_set_data(change, odata);
	osync_data_unref(odata);
	
	osync_context_report_success(ctx);
	
	g_free(filename);
	
	osync_trace(TRACE_EXIT, "%s", __func__);
	return TRUE;

error_free_data:
	g_free(data);
error:
	g_free(filename);
	osync_context_report_osyncerror(ctx, error);
	osync_trace(TRACE_EXIT_ERROR, "%s: %s", __func__, osync_error_print(&error));
	osync_error_unref(&error);
	return FALSE;
}

static osync_bool osync_filesync_write(void *data, OSyncPluginInfo *info, OSyncContext *ctx, OSyncChange *change)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p)", __func__, data, info, ctx, change);
	OSyncObjTypeSink *sink = osync_plugin_info_get_sink(info);
	OSyncFileDir *dir = osync_objtype_sink_get_userdata(sink);
	OSyncError *error = NULL;
	OSyncData *odata = NULL;
	char *buffer = NULL;
	unsigned int size = 0;
	
	char *filename = g_strdup_printf ("%s/%s", dir->path, osync_change_get_uid(change));
			
	switch (osync_change_get_changetype(change)) {
		case OSYNC_CHANGE_TYPE_DELETED:
			if (!remove(filename) == 0) {
				osync_error_set(&error, OSYNC_ERROR_FILE_NOT_FOUND, "Unable to write");
				goto error;
			}
			break;
		case OSYNC_CHANGE_TYPE_ADDED:
			if (g_file_test(filename, G_FILE_TEST_EXISTS)) {
                                 const char *newid = g_strdup_printf ("%s-new", osync_change_get_uid(change));
                                 osync_change_set_uid(change, newid);
                                 osync_filesync_write(data, info, ctx, change);
                                //osync_error_set(&error, OSYNC_ERROR_EXISTS, "Entry already exists : %s", filename);
                                //goto error;
			}
			/* No break. Continue below */
		case OSYNC_CHANGE_TYPE_MODIFIED:

			//FIXME add ownership for file-sync

			odata = osync_change_get_data(change);
			g_assert(odata);

			osync_data_get_data(odata, &buffer, &size);
			g_assert(buffer);
			g_assert(size == sizeof(OSyncFileFormat));
			
			OSyncFileFormat *file = (OSyncFileFormat *)buffer;
			
			if (!osync_file_write(filename, file->data, file->size, file->mode, &error))
				goto error;
			break;
		default:
			break;
	}
	
	g_free(filename);
	
	osync_trace(TRACE_EXIT, "%s", __func__);
	return TRUE;
	
error:
	g_free(filename);
	osync_context_report_osyncerror(ctx, error);
	osync_trace(TRACE_EXIT_ERROR, "%s: %s", __func__, osync_error_print(&error));
	osync_error_unref(&error);
	return FALSE;
}

/** Report files on a directory
 *
 * NOTE: If 'dir' is non-empty it MUST start it a slash. This is just
 * to make easier concatenation of the paths, and we can just concatenate
 * fsinfo->path and subdir to get the complete path.
 *
 * @param dir The fsinfo->path subdirectory that should be reported. Use
 *            an empty string to report files on fsinfo->path. Should
 *            start with a slash. See note above.
 *
 */
static void osync_filesync_report_dir(OSyncFileDir *directory, OSyncPluginInfo *info, const char *subdir, OSyncContext *ctx)
{
	GError *gerror = NULL;
	const char *de = NULL;
	char *path = NULL;
	GDir *dir = NULL;
	OSyncError *error = NULL;
	
	osync_trace(TRACE_ENTRY, "%s(%p, %s, %p)", __func__, directory, subdir, ctx);

	OSyncFormatEnv *formatenv = osync_plugin_info_get_format_env(info);

	path = g_build_filename(directory->path, subdir, NULL);
	osync_trace(TRACE_INTERNAL, "path %s", path);
	
	dir = g_dir_open(path, 0, &gerror);
	if (!dir) {
		/*FIXME: Permission errors may make files to be reported as deleted.
		 * Make fs_report_dir() able to report errors
		 */
		osync_error_set(&error, OSYNC_ERROR_GENERIC, "Unable to open directory %s: %s", path, gerror ? gerror->message : "None");
		osync_context_report_osyncwarning(ctx, error);
		osync_error_unref(&error);
		osync_trace(TRACE_EXIT_ERROR, "%s: %s", __func__, osync_error_print(&error));
		return;
	}

	while ((de = g_dir_read_name(dir))) {
		char *filename = g_build_filename(path, de, NULL);
		char *relative_filename = NULL;
		if (!subdir)
			relative_filename = g_strdup(de);
		else
			relative_filename = g_build_filename(subdir, de, NULL);
			
		osync_trace(TRACE_INTERNAL, "path2 %s %s", filename, relative_filename);
		
		if (g_file_test(filename, G_FILE_TEST_IS_DIR)) {
			/* Recurse into subdirectories */
			if (directory->recursive)
				osync_filesync_report_dir(directory, info, relative_filename, ctx);
		} else if (g_file_test(filename, G_FILE_TEST_IS_REGULAR)) {
			
			struct stat buf;
			stat(filename, &buf);

			/* Report normal files */
			OSyncChange *change = osync_change_new(&error);
			if (!change) {
				osync_context_report_osyncwarning(ctx, error);
				osync_error_unref(&error);
				g_free(relative_filename);
				continue;
			}

			osync_change_set_uid(change, relative_filename);

			char *hash = osync_filesync_generate_hash(&buf);
			osync_change_set_hash(change, hash);
			g_free(hash);

			OSyncChangeType type = osync_hashtable_get_changetype(directory->hashtable, change);
			osync_change_set_changetype(change, type);

			osync_hashtable_update_change(directory->hashtable, change);

			if (type == OSYNC_CHANGE_TYPE_UNMODIFIED) {
				g_free(filename);
				g_free(relative_filename);
				osync_change_unref(change);
				continue;
			}

			char *data;
			unsigned int size;
			OSyncError *error = NULL;
			if (!osync_file_read(filename, &data, &size, &error)) {
				osync_change_unref(change);
				osync_context_report_osyncwarning(ctx, error);
				osync_error_unref(&error);
				g_free(filename);
				g_free(relative_filename);
				continue;
			}

			OSyncData *odata = NULL;

			OSyncFileFormat *file = osync_try_malloc0(sizeof(OSyncFileFormat), &error);
			if (!file) {
				osync_change_unref(change);
				osync_context_report_osyncwarning(ctx, error);
				osync_error_unref(&error);
				g_free(filename);
				g_free(relative_filename);
				continue;
			}

			file->data = data;
			file->size = size;
			file->path = g_strdup(relative_filename);
			
		        OSyncObjFormat *fileformat = osync_format_env_find_objformat(formatenv, "file");

			odata = osync_data_new((char *)file, sizeof(OSyncFileFormat), fileformat, &error);
			if (!odata) {
				osync_change_unref(change);
				osync_context_report_osyncwarning(ctx, error);
				osync_error_unref(&error);
				g_free(data);
				g_free(filename);
				g_free(relative_filename);
				g_free(file->path);
				continue;
			}

			osync_data_set_objtype(odata, osync_objtype_sink_get_name(directory->sink));
			osync_change_set_data(change, odata);
			osync_data_unref(odata);
	
			osync_context_report_change(ctx, change);
			
			osync_change_unref(change);
		}

		g_free(filename);
		g_free(relative_filename);

	}

	g_dir_close(dir);

	g_free(path);
	osync_trace(TRACE_EXIT, "%s", __func__);
}

static void osync_filesync_get_changes(void *data, OSyncPluginInfo *info, OSyncContext *ctx)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);
	OSyncObjTypeSink *sink = osync_plugin_info_get_sink(info);
	OSyncFileDir *dir = osync_objtype_sink_get_userdata(sink);
	OSyncFormatEnv *formatenv = osync_plugin_info_get_format_env(info);
	OSyncError *error = NULL;
	
	if (osync_objtype_sink_get_slowsync(dir->sink)) {
		osync_trace(TRACE_INTERNAL, "Slow sync requested");
		if (!osync_hashtable_slowsync(dir->hashtable, &error))
		{
			osync_context_report_osyncerror(ctx, error);
			osync_trace(TRACE_EXIT_ERROR, "%s - %s", __func__, osync_error_print(&error));
			osync_error_unref(&error);
			return;
		}
	}
	
	osync_trace(TRACE_INTERNAL, "get_changes for %s", osync_objtype_sink_get_name(sink));

	osync_filesync_report_dir(dir, info, NULL, ctx);
	
	OSyncList *u, *uids = osync_hashtable_get_deleted(dir->hashtable);
	for (u = uids; u; u = u->next) {
		OSyncChange *change = osync_change_new(&error);
		if (!change) {
			osync_context_report_osyncwarning(ctx, error);
			osync_error_unref(&error);
			continue;
		}
		
		const char *uid = u->data;
		osync_change_set_uid(change, uid);
		osync_change_set_changetype(change, OSYNC_CHANGE_TYPE_DELETED);
		
	        OSyncObjFormat *fileformat = osync_format_env_find_objformat(formatenv, "file");

		OSyncData *odata = osync_data_new(NULL, 0, fileformat, &error);
		if (!odata) {
			osync_change_unref(change);
			osync_context_report_osyncwarning(ctx, error);
			osync_error_unref(&error);
			continue;
		}
		
		osync_data_set_objtype(odata, osync_objtype_sink_get_name(sink));
		osync_change_set_data(change, odata);
		osync_data_unref(odata);
		
		osync_context_report_change(ctx, change);
		
		osync_hashtable_update_change(dir->hashtable, change);
	
		osync_change_unref(change);
	}
	osync_list_free(uids);
	
	osync_context_report_success(ctx);
	osync_trace(TRACE_EXIT, "%s", __func__);
}

static void osync_filesync_commit_change(void *data, OSyncPluginInfo *info, OSyncContext *ctx, OSyncChange *change)
{
	osync_trace(TRACE_ENTRY, "%s", __func__);
	OSyncObjTypeSink *sink = osync_plugin_info_get_sink(info);
	OSyncFileDir *dir = osync_objtype_sink_get_userdata(sink);
	
	char *filename = NULL;
	
	if (!osync_filesync_write(data, info, ctx, change)) {
		osync_trace(TRACE_EXIT_ERROR, "%s", __func__);
		return;
	}
	
	filename = g_strdup_printf ("%s/%s", dir->path, osync_change_get_uid(change));
	char *hash = NULL;
	
	if (osync_change_get_changetype(change) != OSYNC_CHANGE_TYPE_DELETED) {
		struct stat buf;
		stat(filename, &buf);
		hash = osync_filesync_generate_hash(&buf);
		osync_change_set_hash(change, hash);
	}
	g_free(filename);

	osync_hashtable_update_change(dir->hashtable, change);
	g_free(hash);
	
	osync_context_report_success(ctx);
	
	osync_trace(TRACE_EXIT, "%s", __func__);
}

static void osync_filesync_sync_done(void *data, OSyncPluginInfo *info, OSyncContext *ctx)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, ctx);

	OSyncError *error = NULL;

	OSyncObjTypeSink *sink = osync_plugin_info_get_sink(info);
	OSyncFileDir *dir = osync_objtype_sink_get_userdata(sink);

	char *anchorpath = g_strdup_printf("%s/anchor.db", osync_plugin_info_get_configdir(info));
	char *path_field = g_strdup_printf("path_%s", osync_objtype_sink_get_name(sink));
	osync_anchor_update(anchorpath, path_field, dir->path);
	g_free(anchorpath);
	g_free(path_field);

	if (!osync_hashtable_save(dir->hashtable, &error))
		goto error;
	
	osync_context_report_success(ctx);
	
	osync_trace(TRACE_EXIT, "%s", __func__);
	return;

error:
	osync_context_report_osyncerror(ctx, error);
	osync_trace(TRACE_EXIT_ERROR, "%s: %s", __func__, osync_error_print(&error));
	osync_error_unref(&error);
	return;
}

/* In initialize, we get the config for the plugin. Here we also must register
 * all _possible_ objtype sinks. */
static void *osync_filesync_initialize(OSyncPlugin *plugin, OSyncPluginInfo *info, OSyncError **error)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p)", __func__, info, error);

	OSyncFileEnv *env = osync_try_malloc0(sizeof(OSyncFileEnv), error);
	if (!env)
		goto error;
	
	OSyncPluginConfig *config = osync_plugin_info_get_config(info);
	assert(config);


	int i, numobjs = osync_plugin_info_num_objtypes(info);
	for (i = 0; i < numobjs; i++) {
		OSyncFileDir *dir = osync_try_malloc0(sizeof(OSyncFileDir), error);
		if (!dir)
			goto error_free_env;

		dir->sink = osync_plugin_info_nth_objtype(info, i);
		assert(dir->sink);

		const char *objtype = osync_objtype_sink_get_name(dir->sink);
		OSyncPluginResource *res = osync_plugin_config_find_active_resource(config, objtype);
		dir->path = osync_plugin_resource_get_path(res);
		if (!dir->path) {
			osync_error_set(error, OSYNC_ERROR_MISCONFIGURATION, "Path for object type \"%s\" is not configured.", objtype);
			goto error_free_env;
		}

		OSyncList *s = osync_plugin_resource_get_objformat_sinks(res);
		for (; s; s = s->next) {
			OSyncObjFormatSink *fsink = s->data;
			const char *objformat = osync_objformat_sink_get_objformat(fsink);
			assert(objformat);
			
			/* TODO: Implement objformat sanity check in OpenSync Core */ 
			if (strcmp(objformat, "file")) {
				osync_error_set(error, OSYNC_ERROR_MISCONFIGURATION, "Format \"%s\" is not supported by file-sync. Only Format \"file\" is currently supported by the file-sync plugin.", objformat);
				goto error_free_env;
			}

		}

		/* All sinks have the same functions of course */
		OSyncObjTypeSinkFunctions functions;
		memset(&functions, 0, sizeof(functions));
		functions.get_changes = osync_filesync_get_changes;
		functions.commit = osync_filesync_commit_change;
		functions.read = osync_filesync_read;
		functions.write = osync_filesync_write;
		functions.sync_done = osync_filesync_sync_done;
		
		/* We pass the OSyncFileDir object to the sink, so we dont have to look it up
		 * again once the functions are called */
		osync_objtype_sink_set_functions(dir->sink, functions, dir);

		osync_trace(TRACE_INTERNAL, "The configdir: %s", osync_plugin_info_get_configdir(info));
		char *tablepath = g_strdup_printf("%s/hashtable.db", osync_plugin_info_get_configdir(info));
		dir->hashtable = osync_hashtable_new(tablepath, objtype, error);
		g_free(tablepath);
	
		if (!dir->hashtable)
			goto error_free_env;

		if (!osync_hashtable_load(dir->hashtable, error))
			goto error_free_env;

		char *anchorpath = g_strdup_printf("%s/anchor.db", osync_plugin_info_get_configdir(info));
		char *path_field = g_strdup_printf("path_%s", osync_objtype_sink_get_name(dir->sink));
		if (!osync_anchor_compare(anchorpath, path_field, dir->path))
			osync_objtype_sink_set_slowsync(dir->sink, TRUE);
		g_free(anchorpath);
		g_free(path_field);
	
		if (!g_file_test(dir->path, G_FILE_TEST_IS_DIR)) {
			osync_error_set(error, OSYNC_ERROR_GENERIC, "%s is not a directory", dir->path);
			goto error_free_env;
		}
	}

	osync_trace(TRACE_EXIT, "%s: %p", __func__, env);
	return (void *)env;

error_free_env:
	free_env(env);
error:
	osync_trace(TRACE_EXIT_ERROR, "%s: %s", __func__, osync_error_print(error));
	return NULL;
}

static void osync_filesync_finalize(void *data)
{
	OSyncFileEnv *env = data;

	free_env(env);
}

/* Here we actually tell opensync which sinks are available. For this plugin, we
 * just report all objtype as available. Since the resource are configured like this. */
static osync_bool osync_filesync_discover(void *data, OSyncPluginInfo *info, OSyncError **error)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, error);
	
	int i, numobjs = osync_plugin_info_num_objtypes(info);
	for (i = 0; i < numobjs; i++) {
		OSyncObjTypeSink *sink = osync_plugin_info_nth_objtype(info, i);
		g_assert(sink);

		osync_objtype_sink_set_available(sink, TRUE);
	}
	
	OSyncVersion *version = osync_version_new(error);
	osync_version_set_plugin(version, "file-sync");
	//osync_version_set_modelversion(version, "version");
	//osync_version_set_firmwareversion(version, "firmwareversion");
	//osync_version_set_softwareversion(version, "softwareversion");
	//osync_version_set_hardwareversion(version, "hardwareversion");
	osync_plugin_info_set_version(info, version);
	osync_version_unref(version);

	/* we can set here the capabilities, but for the file-sync
	 * plugin they are static and shipped with opensync */

	osync_trace(TRACE_EXIT, "%s", __func__);
	return TRUE;
}

osync_bool get_sync_info(OSyncPluginEnv *env, OSyncError **error)
{
	OSyncPlugin *plugin = osync_plugin_new(error);
	if (!plugin)
		goto error;
	
	osync_plugin_set_name(plugin, "file-sync");
	osync_plugin_set_longname(plugin, "File Synchronization Plugin");
	osync_plugin_set_description(plugin, "Plugin to synchronize files on the local filesystem");
	
	osync_plugin_set_initialize(plugin, osync_filesync_initialize);
	osync_plugin_set_finalize(plugin, osync_filesync_finalize);
	osync_plugin_set_discover(plugin, osync_filesync_discover);
	
	osync_plugin_env_register_plugin(env, plugin);
	osync_plugin_unref(plugin);
	
	return TRUE;
	
error:
	osync_trace(TRACE_ERROR, "Unable to register: %s", osync_error_print(error));
	osync_error_unref(error);
	return FALSE;
}

int get_version(void)
{
	return 1;
}
