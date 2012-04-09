#include <ngx_http_hs_module.h>

static void *ngx_http_hs_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_hs_init_main_conf(ngx_conf_t *cf, void *conf);

static ngx_command_t ngx_http_hs_commands[] = {

    { ngx_string("hs_route_db"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_hs_main_conf_t, route_db),
      NULL },

    { ngx_string("hs_key_material_db"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_hs_main_conf_t, key_material_db),
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_hs_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_hs_create_main_conf,         /* create main configuration */
    ngx_http_hs_init_main_conf,           /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_hs_module = {
    NGX_MODULE_V1,
    &ngx_http_hs_module_ctx,              /* module context */
    ngx_http_hs_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_hs_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_hs_main_conf_t  *maincf;

    maincf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hs_main_conf_t));
    if (maincf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     maincf->route_db = { 0, NULL };
     *     maincf->key_material_db = { 0, NULL };
     *     maincf->tcb_route_db = NULL;
     *     maincf->tcb_key_material_db = NULL;
     */

    return maincf;
}

/* would like to use the handles in the conf_t, but unfortunately these handles
 * are super-global, as the tcb lib doesn't allow opening a file a second time...
 */
static TCBDB* global_tcb_route_db = NULL;
static TCBDB* global_tcb_key_material_db = NULL;

static char *
ngx_http_hs_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_hs_main_conf_t  *maincf = conf;

    if (maincf->route_db.len == 0 && maincf->key_material_db.len == 0) {
        return NGX_CONF_OK;
    }

    if (maincf->route_db.len == 0 || maincf->key_material_db.len == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "route_db or key_material_db used without each other");
        return NGX_CONF_ERROR;
    }

    if (global_tcb_route_db != NULL) {
        tcbdbclose(global_tcb_route_db);
    } else {
        global_tcb_route_db = tcbdbnew();
    }

    if (!tcbdbopen(global_tcb_route_db, (const char*)maincf->route_db.data, BDBOREADER)) {
        int err = tcbdbecode(global_tcb_route_db);
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "could not open hs_route_db \"%s\" error: (%d) %s", maincf->route_db.data, err, tcbdberrmsg(err));
        return NGX_CONF_ERROR;
    }
    maincf->tcb_route_db = global_tcb_route_db;

    if (global_tcb_key_material_db != NULL) {
        tcbdbclose(global_tcb_key_material_db);
    } else {
        global_tcb_key_material_db = tcbdbnew();
    }

    if (!tcbdbopen(global_tcb_key_material_db, (const char*)maincf->key_material_db.data, BDBOREADER)) {
        int err = tcbdbecode(global_tcb_key_material_db);
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "could not open hs_key_material_db \"%s\" error: (%d) %s", maincf->key_material_db.data, err, tcbdberrmsg(err));
        return NGX_CONF_ERROR;
    }
    maincf->tcb_key_material_db = global_tcb_key_material_db;

    return NGX_CONF_OK;
}

