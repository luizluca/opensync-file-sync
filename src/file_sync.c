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
#include "filename_scape.h"
#include "file.h"
#include <opensync/opensync-version.h>
#include <assert.h>
#include <stdlib.h>

static void free_dir(OSyncFileDir *dir)
{
	if (dir->sink)
		osync_objtype_sink_unref(dir->sink);

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

static void osync_filesync_connect(OSyncObjTypeSink *sink, OSyncPluginInfo *info, OSyncContext *ctx, void *userdata)
{
	OSyncError *error = NULL;
	
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p)", __func__, sink, info, ctx, userdata);

	OSyncFileDir *dir = userdata;
	OSyncSinkStateDB *state_db = osync_objtype_sink_get_state_db(sink); 
	osync_bool pathmatch;

	if (!osync_sink_state_equal(state_db, "path", dir->path, &pathmatch, &error))
		goto error;

	if (!pathmatch)
		osync_context_report_slowsync(ctx);

	if (!g_file_test(dir->path, G_FILE_TEST_IS_DIR)) {
		osync_error_set(&error, OSYNC_ERROR_GENERIC, "\"%s\" is not a directory", dir->path);
		goto error;
	}
	
	osync_context_report_success(ctx);
	
	osync_trace(TRACE_EXIT, "%s", __func__);
	return;
	
error:
	osync_context_report_osyncerror(ctx, error);
	osync_trace(TRACE_EXIT_ERROR, "%s: %s", __func__, osync_error_print(&error));
	osync_error_unref(&error);
}

//typedef void (* OSyncSinkWriteFn) 
//typedef void (* OSyncSinkCommittedAllFn) (void *data, OSyncPluginInfo *info, OSyncContext *ctx);


static void osync_filesync_read(OSyncObjTypeSink *sink, OSyncPluginInfo *info, OSyncContext *ctx, OSyncChange *change, void *userdata)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p, %p)", __func__, sink , info, ctx, change, userdata);

	OSyncFileDir *dir = userdata;
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
	return;

error_free_data:
	g_free(data);
error:
	g_free(filename);
	osync_context_report_osyncerror(ctx, error);
	osync_trace(TRACE_EXIT_ERROR, "%s: %s", __func__, osync_error_print(&error));
	osync_error_unref(&error);
	return;
}

static osync_bool osync_filesync_write(OSyncObjTypeSink *sink, OSyncPluginInfo *info, OSyncContext *ctx, OSyncChange *change, void *userdata)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p, %p)", __func__, sink, info, ctx, change, userdata);

	OSyncFileDir *dir = userdata;
	OSyncError *error = NULL;
	OSyncData *odata = NULL;
	char *buffer = NULL;
	unsigned int size = 0;
	
	char *filename = NULL, *tmp = NULL;
	if (!(tmp = strdup(osync_change_get_uid(change))))
		goto error;

	filename_scape_characters(tmp);

	filename = g_strdup_printf ("%s%c%s", dir->path, G_DIR_SEPARATOR, tmp);
	free(tmp);

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
				osync_filesync_write(sink, info, ctx, change, userdata);
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
			if (size != sizeof(OSyncFileFormat)) {
				osync_error_set(&error, OSYNC_ERROR_MISCONFIGURATION,
					"The plugin file-sync only supports file format. Please re-configure and discover the plugin again.");
				goto error;
			}
			
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
	OSyncHashTable *hashtable = osync_objtype_sink_get_hashtable(directory->sink); 

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

			OSyncChangeType type = osync_hashtable_get_changetype(hashtable, change);
			osync_change_set_changetype(change, type);

			osync_hashtable_update_change(hashtable, change);

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

static void osync_filesync_get_changes(OSyncObjTypeSink *sink, OSyncPluginInfo *info, OSyncContext *ctx, osync_bool slow_sync, void *userdata)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %i, %p)", __func__, sink, info, ctx, slow_sync, userdata);

	OSyncFileDir *dir = userdata;
	OSyncFormatEnv *formatenv = osync_plugin_info_get_format_env(info);
	OSyncHashTable *hashtable = osync_objtype_sink_get_hashtable(sink); 

	OSyncError *error = NULL;
	
	if (slow_sync) {
		osync_trace(TRACE_INTERNAL, "Slow sync requested");
		if (!osync_hashtable_slowsync(hashtable, &error))
		{
			osync_context_report_osyncerror(ctx, error);
			osync_trace(TRACE_EXIT_ERROR, "%s - %s", __func__, osync_error_print(&error));
			osync_error_unref(&error);
			return;
		}
	}
	
	osync_trace(TRACE_INTERNAL, "get_changes for %s", osync_objtype_sink_get_name(sink));

	osync_filesync_report_dir(dir, info, NULL, ctx);
	
	OSyncList *u, *uids = osync_hashtable_get_deleted(hashtable);
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
		
		osync_hashtable_update_change(hashtable, change);
	
		osync_change_unref(change);
	}
	osync_list_free(uids);
	
	osync_context_report_success(ctx);
	osync_trace(TRACE_EXIT, "%s", __func__);
}

static void osync_filesync_commit_change(OSyncObjTypeSink *sink, OSyncPluginInfo *info, OSyncContext *ctx, OSyncChange *change, void *userdata)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p, %p)", __func__, sink, info, ctx, change, userdata);

	OSyncFileDir *dir = userdata;
	OSyncHashTable *hashtable = osync_objtype_sink_get_hashtable(sink); 
	
	char *filename = NULL, *tmp;
	
	if (!osync_filesync_write(sink, info, ctx, change, userdata)) {
		osync_trace(TRACE_EXIT_ERROR, "%s", __func__);
		return;
	}
	if (!(tmp = strdup(osync_change_get_uid(change)))) {
		osync_trace(TRACE_EXIT_ERROR, "%s", __func__);
		return;
	}
	filename_scape_characters(tmp);

	filename = g_strdup_printf ("%s/%s", dir->path, tmp);
	free(tmp);
	char *hash = NULL;
	
	if (osync_change_get_changetype(change) != OSYNC_CHANGE_TYPE_DELETED) {
		struct stat buf;
		stat(filename, &buf);
		hash = osync_filesync_generate_hash(&buf);
		osync_change_set_hash(change, hash);
	}
	g_free(filename);

	osync_hashtable_update_change(hashtable, change);
	g_free(hash);
	
	osync_context_report_success(ctx);
	
	osync_trace(TRACE_EXIT, "%s", __func__);
}

static void osync_filesync_sync_done(OSyncObjTypeSink *sink, OSyncPluginInfo *info, OSyncContext *ctx, void *userdata)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p, %p)", __func__, sink, info, ctx, userdata);

	OSyncError *error = NULL;

	OSyncFileDir *dir = userdata;
	OSyncSinkStateDB *state_db = osync_objtype_sink_get_state_db(sink); 

	if (!osync_sink_state_set(state_db, "path", dir->path, &error))
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
	OSyncList *s , *sinks = NULL;

	osync_trace(TRACE_ENTRY, "%s(%p, %p)", __func__, info, error);

	OSyncFileEnv *env = osync_try_malloc0(sizeof(OSyncFileEnv), error);
	if (!env)
		goto error;
	
	OSyncPluginConfig *config = osync_plugin_info_get_config(info);
	assert(config);


	GList *pathes = NULL;
	sinks = osync_plugin_info_get_objtype_sinks(info);
	for (s = sinks; s; s = s->next) {
		OSyncFileDir *dir = osync_try_malloc0(sizeof(OSyncFileDir), error);
		if (!dir)
			goto error_free_env;

		dir->env = env;
		dir->sink = (OSyncObjTypeSink *) s->data;
		assert(dir->sink);

		const char *objtype = osync_objtype_sink_get_name(dir->sink);
		OSyncPluginResource *res = osync_plugin_config_find_active_resource(config, objtype);
		dir->path = osync_plugin_resource_get_path(res);
		if ((!dir->path) || (!strlen(dir->path))) {
			osync_error_set(error, OSYNC_ERROR_MISCONFIGURATION, "Path for object type \"%s\" is not configured.", objtype);
			goto error_free_env;
		}
		if(g_list_find_custom(pathes, dir->path, (GCompareFunc)strcmp)) {
			osync_error_set(error, OSYNC_ERROR_MISCONFIGURATION, "Path for objtype \"%s\" defined for more than one objtype sink in configuration.", objtype);
			goto error_free_env;
		}
		pathes = g_list_append(pathes, g_strdup(dir->path));

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
		osync_objtype_sink_set_connect_func(dir->sink, osync_filesync_connect);
		osync_objtype_sink_set_get_changes_func(dir->sink, osync_filesync_get_changes);
		osync_objtype_sink_set_commit_func(dir->sink, osync_filesync_commit_change);
		osync_objtype_sink_set_read_func(dir->sink, osync_filesync_read);
		osync_objtype_sink_set_sync_done_func(dir->sink, osync_filesync_sync_done);
		
		/* We pass the OSyncFileDir object to the sink, so we dont have to look it up
		 * again once the functions are called */
		osync_objtype_sink_set_userdata(dir->sink, dir);

		/* Request a state database from the framework. */
		osync_objtype_sink_enable_state_db(dir->sink, TRUE); 

		/* Request an hashtable from the framework. */
		osync_objtype_sink_enable_hashtable(dir->sink, TRUE);
	}
	osync_list_free(sinks);

	if (pathes) {
		g_list_foreach(pathes, (GFunc)g_free, NULL);
		g_list_free(pathes);
	}

	osync_trace(TRACE_EXIT, "%s: %p", __func__, env);
	return (void *)env;

error_free_env:
	free_env(env);
error:
	if (sinks)
		osync_list_free(sinks);

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
static osync_bool osync_filesync_discover(OSyncPluginInfo *info, void *data, OSyncError **error)
{
	osync_trace(TRACE_ENTRY, "%s(%p, %p, %p)", __func__, data, info, error);
	
	OSyncList *s, *sinks = osync_plugin_info_get_objtype_sinks(info);
	for (s = sinks; s; s = s->next) {
		OSyncObjTypeSink *sink = (OSyncObjTypeSink *) s->data;
		g_assert(sink);

		osync_objtype_sink_set_available(sink, TRUE);
	}
	osync_list_free(sinks);
	
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
