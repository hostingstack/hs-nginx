#ifndef _NGX_HTTP_HS_H_INCLUDED_
#define _NGX_HTTP_HS_H_INCLUDED_

#include <tcutil.h>
#include <tcbdb.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

extern ngx_module_t ngx_http_hs_module;

typedef struct {
    ngx_str_t                       route_db;
    ngx_str_t                       key_material_db;

    /* TCB handles */
    TCBDB*                          tcb_route_db;
    TCBDB*                          tcb_key_material_db;

    u_char                         *file;
    ngx_uint_t                      line;
} ngx_http_hs_main_conf_t;

typedef struct {
    size_t primary_agent_ip_strsize;
    u_char primary_agent_ip_strbuf[16];
    size_t secondary_agent_ip_strsize;
    u_char secondary_agent_ip_strbuf[16];
    size_t di_nlen;
    u_char di_name[64];
    size_t envtype_strsize;
    u_char envtype_strbuf[32];
    uint32_t key_material_id;
} hs_route_t;

typedef struct {
    uint32_t version;
    size_t certificate_size;
    size_t key_size;
} hs_key_material_header_t;

#endif

