#include <ngx_http_hs_module.h>

#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
#error "ngx_http_virtualssl_module requires SSL_CTRL_SET_TLSEXT_HOSTNAME to build"
#endif

static void *ngx_http_virtualssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_virtualssl_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);

typedef struct {
    ngx_flag_t                      enable;

    u_char                         *file;
    ngx_uint_t                      line;
} ngx_http_virtualssl_srv_conf_t;

static ngx_command_t  ngx_http_virtualssl_commands[] = {

    { ngx_string("virtualssl"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_virtualssl_srv_conf_t, enable),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_virtualssl_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_virtualssl_create_srv_conf,   /* create server configuration */
    ngx_http_virtualssl_merge_srv_conf,    /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_virtualssl_module = {
    NGX_MODULE_V1,
    &ngx_http_virtualssl_module_ctx,       /* module context */
    ngx_http_virtualssl_commands,          /* module directives */
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
ngx_http_virtualssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_virtualssl_srv_conf_t  *modcf;

    modcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_virtualssl_srv_conf_t));
    if (modcf == NULL) {
        return NULL;
    }

    modcf->enable = NGX_CONF_UNSET;

    return modcf;
}

/* BIO memory buffer based re-implementation of SSL_CTX_use_certificate_chain_file */
static int
ngx_http_virtualssl_SSL_CTX_use_certificate_chain_buffer(SSL_CTX* ctx, char* buffer)
{
    BIO                      *in;
    X509                     *x, *ca;
    int                       ret;
    unsigned long             err;

    ERR_clear_error();

    in = BIO_new_mem_buf(buffer, -1);
    if (in == NULL) {
        return NGX_ERROR;
    }
    x = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    if (x == NULL) {
        BIO_free(in);
        return NGX_ERROR;
    }

    ret = SSL_CTX_use_certificate(ctx, x);
    if (ERR_peek_error() != 0) {
        ret = 0;
    }
    if (ret) {
        if (ctx->extra_certs != NULL) {
            sk_X509_pop_free(ctx->extra_certs, X509_free);
            ctx->extra_certs = NULL;
        }

        while ((ca = PEM_read_bio_X509(in,NULL,ctx->default_passwd_callback,ctx->default_passwd_callback_userdata))
               != NULL) {
            if (!SSL_CTX_add_extra_chain_cert(ctx, ca)) {
                X509_free(ca);
                ret = 0;
                goto end;
            }
        }

        err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
            ERR_clear_error();
        } else {
            ret = 0;
        }
    }

end:
    X509_free(x);
    BIO_free(in);
    return NGX_OK;
}

/* BIO memory buffer based re-implementation of SSL_CTX_use_PrivateKey_file */
static int
ngx_http_virtualssl_SSL_CTX_use_PrivateKey_buffer(SSL_CTX* ctx, char* buffer)
{
    BIO                      *in;
    EVP_PKEY                 *pkey;
    int                       ret;

    in = BIO_new_mem_buf(buffer, -1);
    if (in == NULL) {
        return NGX_ERROR;
    }

    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    if (pkey == NULL) {
        BIO_free(in);
        return NGX_ERROR;
    }

    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
    BIO_free(in);

    return (ret == 0) ? NGX_OK : NGX_ERROR;
}

int
ngx_http_virtualssl_handle_sni(ngx_ssl_conn_t *ssl_conn, u_char *host, size_t len)
{
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_http_ssl_srv_conf_t    *sscf;
    ngx_ssl_t                  *ssl;
    ngx_str_t                   dhparam_file;
    ngx_http_hs_main_conf_t   *hscf;
    ngx_http_virtualssl_srv_conf_t   *vscf;
    hs_key_material_header_t  *key_material;
    hs_route_t                *route;
    int                         tcb_s;
    char                       *buf;
    u_char                      key_material_lookup_key[32];

    c = ngx_ssl_get_connection(ssl_conn);
    r = c->data;

    hscf = ngx_http_get_module_main_conf(r, ngx_http_hs_module);
    vscf = ngx_http_get_module_srv_conf(r, ngx_http_virtualssl_module);
    if (hscf == NULL || vscf == NULL || hscf->tcb_route_db == NULL ||
        hscf->tcb_key_material_db == NULL || !vscf->enable) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "[virtualssl] SSL server name: \"%s\"", host);

    route = (hs_route_t*)tcbdbget(hscf->tcb_route_db, host, len, &tcb_s);
    if (route == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "virtualssl: unknown route");
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (route->key_material_id == 0) {
        /* no SSL configured for this hostname */
        return SSL_TLSEXT_ERR_NOACK;
    }

    (void)ngx_snprintf(key_material_lookup_key, 30, "%uD%Z", route->key_material_id);
    key_material_lookup_key[31] = '\0';
    key_material = (hs_key_material_header_t*)tcbdbget(hscf->tcb_key_material_db, key_material_lookup_key, strlen((char*)key_material_lookup_key), &tcb_s);
    if (key_material == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "virtualssl: key_material %d not found", route->key_material_id);
        return SSL_TLSEXT_ERR_NOACK;
    }

    ssl = ngx_palloc(r->pool, sizeof(ngx_ssl_t));

    sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);

    ssl->log = c->log;
    if (ngx_ssl_create(ssl, sscf->protocols, sscf) != NGX_OK) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "virtualssl: ngx_ssl_create failed");
        return SSL_TLSEXT_ERR_NOACK;
    }

    buf = (char*)key_material;
    buf += sizeof(hs_key_material_header_t);
    if (ngx_http_virtualssl_SSL_CTX_use_certificate_chain_buffer(ssl->ctx, buf) != NGX_OK) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "virtualssl: ngx_http_virtualssl_SSL_CTX_use_certificate_chain_buffer failed");
        return SSL_TLSEXT_ERR_NOACK;
    }
    buf += key_material->certificate_size;
    if (ngx_http_virtualssl_SSL_CTX_use_PrivateKey_buffer(ssl->ctx, buf) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "virtualssl: ngx_http_virtualssl_SSL_CTX_use_PrivateKey_buffer failed");
        return SSL_TLSEXT_ERR_NOACK;
    }

    SSL_CTX_set_cipher_list(ssl->ctx, (const char *) sscf->ciphers.data);
    if (sscf->prefer_server_ciphers) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    /* HACK: ngx_ssl_dhparam uses it's own built-in dhparams if dhparam_file.len == 0,
       and _then_ it doesn't need a config pointer. */
    dhparam_file.len = 0;
    if (ngx_ssl_dhparam(NULL, ssl, &dhparam_file) != NGX_OK) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "virtualssl: ngx_ssl_dhparam failed");
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (ngx_ssl_session_cache(ssl, &ngx_http_ssl_sess_id_ctx,
                              sscf->builtin_session_cache,
                              sscf->shm_zone, sscf->session_timeout) != NGX_OK) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      "virtualssl: ngx_ssl_session_cache failed");
        return SSL_TLSEXT_ERR_NOACK;
    }

    SSL_set_SSL_CTX(ssl_conn, ssl->ctx);

    return SSL_TLSEXT_ERR_OK;
}

static char *
ngx_http_virtualssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_virtualssl_srv_conf_t *prev = parent;
    ngx_http_virtualssl_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}

