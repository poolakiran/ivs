/****************************************************************
 *
 *        Copyright 2014, Big Switch Networks, Inc.
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *        http://www.eclipse.org/legal/epl-v10.html
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#include <pipeline/pipeline.h>
#include <stdlib.h>

#include <ivs/ivs.h>
#include <loci/loci.h>
#include <OVSDriver/ovsdriver.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include <AIM/aim_list.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <pthread.h>

#include "pipeline_lua_int.h"

#define AIM_LOG_MODULE_NAME pipeline_lua
#include <AIM/aim_log.h>

struct table {
    list_links_t links;
    lua_State *lua;
    char *name;
    int ref_add;
    int ref_modify;
    int ref_delete;
    indigo_core_gentable_t *gentable;
};

static const indigo_core_gentable_ops_t table_ops;
static LIST_DEFINE(tables); /* struct table */

int
pipeline_lua_table_register(lua_State *lua)
{
    const char *name = luaL_checkstring(lua, 1);
    luaL_checktype(lua, 2, LUA_TFUNCTION);
    luaL_checktype(lua, 3, LUA_TFUNCTION);
    luaL_checktype(lua, 4, LUA_TFUNCTION);

    struct table *table = aim_malloc(sizeof(*table));
    table->lua = lua;
    table->name = aim_strdup(name);
    table->ref_delete = luaL_ref(lua, LUA_REGISTRYINDEX);
    table->ref_modify = luaL_ref(lua, LUA_REGISTRYINDEX);
    table->ref_add = luaL_ref(lua, LUA_REGISTRYINDEX);
    list_push(&tables, &table->links);

    indigo_core_gentable_register(
        table->name,
        &table_ops,
        table,
        -1,
        1024,
        &table->gentable);

    return 0;
}

void
pipeline_lua_table_reset(void)
{
    list_links_t *cur, *next;
    LIST_FOREACH_SAFE(&tables, cur, next) {
        struct table *table = container_of(cur, links, struct table);
        indigo_core_gentable_unregister(table->gentable);
        list_remove(&table->links);
        aim_free(table->name);
        aim_free(table);
    }
}

/* table operations */

static indigo_error_t
parse_tlvs(of_list_bsn_tlv_t *tlvs, of_octets_t *data)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_DATA) {
        of_bsn_tlv_data_value_get(&tlv, data);
    } else {
        AIM_LOG_ERROR("expected data value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
table_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct table *table = table_priv;
    of_octets_t key;
    of_octets_t value;

    AIM_LOG_VERBOSE("table %s add", table->name);

    rv = parse_tlvs(key_tlvs, &key);
    if (rv < 0) {
        return rv;
    }

    rv = parse_tlvs(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    lua_rawgeti(table->lua, LUA_REGISTRYINDEX, table->ref_add);
    lua_pushlightuserdata(table->lua, key.data);
    lua_pushinteger(table->lua, key.bytes);
    lua_pushlightuserdata(table->lua, value.data);
    lua_pushinteger(table->lua, value.bytes);
    if (lua_pcall(table->lua, 4, 0, 0) != 0) {
        AIM_LOG_ERROR("Failed to execute table %s add: %s", table->name, lua_tostring(table->lua, -1));
        return INDIGO_ERROR_UNKNOWN;
    }

    *entry_priv = NULL;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
table_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct table *table = table_priv;
    of_octets_t key;
    of_octets_t value;

    AIM_LOG_VERBOSE("table %s modify", table->name);

    rv = parse_tlvs(key_tlvs, &key);
    if (rv < 0) {
        return rv;
    }

    rv = parse_tlvs(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    lua_rawgeti(table->lua, LUA_REGISTRYINDEX, table->ref_modify);
    lua_pushlightuserdata(table->lua, key.data);
    lua_pushinteger(table->lua, key.bytes);
    lua_pushlightuserdata(table->lua, value.data);
    lua_pushinteger(table->lua, value.bytes);
    if (lua_pcall(table->lua, 4, 0, 0) != 0) {
        AIM_LOG_ERROR("Failed to execute table %s modify: %s", table->name, lua_tostring(table->lua, -1));
        return INDIGO_ERROR_UNKNOWN;
    }

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
table_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    indigo_error_t rv;
    struct table *table = table_priv;
    of_octets_t key;

    AIM_LOG_VERBOSE("table %s delete", table->name);

    rv = parse_tlvs(key_tlvs, &key);
    if (rv < 0) {
        return rv;
    }

    lua_rawgeti(table->lua, LUA_REGISTRYINDEX, table->ref_delete);
    lua_pushlightuserdata(table->lua, key.data);
    lua_pushinteger(table->lua, key.bytes);
    if (lua_pcall(table->lua, 2, 0, 0) != 0) {
        AIM_LOG_ERROR("Failed to execute table %s delete: %s", table->name, lua_tostring(table->lua, -1));
        return INDIGO_ERROR_UNKNOWN;
    }

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
table_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* TODO */
}

static const indigo_core_gentable_ops_t table_ops = {
    .add2 = table_add,
    .modify2 = table_modify,
    .del2 = table_delete,
    .get_stats = table_get_stats,
};
