/*
 * nginx cloudrouter module
 *
 * known issues:
 * * config hardcoded for timeouts & cache size
 * * no cache invalidation
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <time.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_http_upstream.h>

#include <assert.h>

#include <ngx_http_hs_module.h>

#define NGX_HTTP_HS_CACHE_SIZE     100
#define NGX_HTTP_HS_CACHE_TIMEOUT   10 /* seconds */

typedef struct {
    ngx_connection_t               *c;
    ngx_http_request_t             *r;
    ngx_http_upstream_t            *u;
    hs_route_t                     route;
    unsigned char                  *buf;
    unsigned char                  *bufend;
    unsigned char                  *bufpos;
    size_t                          sendbufpos;
    int                             done;
    int                             end_marker_count;
} ngx_http_cloudrouter_peer_preconnect_data_t;

typedef struct {
    in_addr_t                       inet_addr;
    in_port_t                       port_n;

    struct sockaddr                *sockaddr;
    socklen_t                       socklen;

    ngx_str_t                       name;

    ngx_str_t                       sendbuf;

    hs_route_t                    *route;
} ngx_http_cloudrouter_peer_t;

typedef struct {
    in_addr_t                       inet_addr;
    in_port_t                       port_n;
    ngx_int_t                       current;
    ngx_int_t                       total;
    void*                           next;
} ngx_http_cloudrouter_remote_t;

#define NGX_HTTP_CLOUDROUTER_DI_NAME_BUFSIZE 64
#define NGX_HTTP_CLOUDROUTER_PRECONNECT_SENDBUFSIZE (NGX_HTTP_CLOUDROUTER_DI_NAME_BUFSIZE+64)
typedef struct {
    ngx_rbtree_node_t               node;
    time_t                          timestamp;
    u_char                          di_name[NGX_HTTP_CLOUDROUTER_DI_NAME_BUFSIZE];
    size_t                          di_nlen;
    ngx_http_cloudrouter_remote_t  *remote;
} ngx_http_cloudrouter_node_t;

static ngx_rbtree_t                *ngx_http_cloudrouter_rbtree;
static ngx_slab_pool_t             *ngx_http_cloudrouter_shpool;

static ngx_int_t ngx_http_cloudrouter_init_upstream_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_cloudrouter_get_upstream_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_http_cloudrouter_free_upstream_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);
static char *ngx_http_cloudrouter_cmd_cloud(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_upstream_init_cloud(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);

static void ngx_http_cloudrouter_peer_preconnect(ngx_http_request_t *r, ngx_http_upstream_t *u);

static void ngx_http_cloudrouter_clear_remotes_locked(ngx_http_cloudrouter_node_t* e, ngx_log_t *log);
static ngx_http_cloudrouter_remote_t* ngx_http_cloudrouter_add_remote_locked(ngx_http_cloudrouter_node_t* e);

static ngx_command_t  ngx_http_cloudrouter_commands[] = {
    { ngx_string("cloud"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_cloudrouter_cmd_cloud,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_cloudrouter_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_cloudrouter_module = {
    NGX_MODULE_V1,
    &ngx_http_cloudrouter_module_ctx,      /* module context */
    ngx_http_cloudrouter_commands,         /* module directives */
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

/* Implementation */

static uint32_t
ngx_http_cloudrouter_hash_route(hs_route_t *route) {
    return ngx_crc32_short(route->di_name, route->di_nlen);
}

/* nginx-style, _locked assumes you have the lock */
static void
ngx_http_cloudrouter_clear_remotes_locked(ngx_http_cloudrouter_node_t* e, ngx_log_t *log) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "CloudRouter: clear_remotes");
    while (e->remote != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "CloudRouter: clear_remotes: e->remote: %p", e->remote);
        ngx_http_cloudrouter_remote_t *remote = e->remote;
        e->remote = e->remote->next;
        ngx_slab_free_locked(ngx_http_cloudrouter_shpool, remote);
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "CloudRouter: clear_remotes done");
}

static ngx_http_cloudrouter_remote_t*
ngx_http_cloudrouter_add_remote_locked(ngx_http_cloudrouter_node_t* e) {
    ngx_http_cloudrouter_remote_t *remote = NULL;
    if (e->remote == NULL) {
        e->remote = ngx_slab_alloc_locked(ngx_http_cloudrouter_shpool, sizeof(ngx_http_cloudrouter_remote_t));
        remote = e->remote;
    } else {
        remote = e->remote;
        while (remote->next != NULL) {
            remote = remote->next;
        }
        remote->next = ngx_slab_alloc_locked(ngx_http_cloudrouter_shpool, sizeof(ngx_http_cloudrouter_remote_t));
        remote = remote->next;
    }
    ngx_memzero(remote, sizeof(ngx_http_cloudrouter_remote_t));
    return remote;
}

static void
ngx_http_cloudrouter_free_node_locked(ngx_http_cloudrouter_node_t *node, ngx_log_t *log) {
    ngx_http_cloudrouter_clear_remotes_locked(node, log);
    ngx_slab_free_locked(ngx_http_cloudrouter_shpool, node);
}

static ngx_http_cloudrouter_node_t*
ngx_http_cloudrouter_get_locked(hs_route_t *route) {
    time_t timeout_before = time(NULL)-NGX_HTTP_HS_CACHE_TIMEOUT;
    ngx_rbtree_node_t *node, *sentinel;
    ngx_http_cloudrouter_node_t *realnode;

    uint32_t hash = ngx_http_cloudrouter_hash_route(route);

    node = ngx_http_cloudrouter_rbtree->root;
    sentinel = ngx_http_cloudrouter_rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->left;
            continue;
        }

        do {
            realnode = (ngx_http_cloudrouter_node_t *) node;

            int rc = ngx_memn2cmp(route->di_name, realnode->di_name, route->di_nlen, realnode->di_nlen);
            if (rc == 0) {
                return realnode;
            }

            node = (rc < 0) ? node->left : node->right;
        } while (node != sentinel && hash == node->key);

        break;
    }

    /* 404 */

    return NULL;
}

static void
ngx_http_cloudrouter_set_hostandport(ngx_http_request_t *r,
                                     ngx_http_cloudrouter_peer_t *peer,
                                     ngx_http_cloudrouter_node_t *e) {
    ngx_http_cloudrouter_remote_t *remote = e->remote;

    if (remote->current > 0) {
        /* find a remote that has no current connections, or use the remote
           with the least current connections */
        ngx_http_cloudrouter_remote_t *rem = e->remote;
        while (rem != NULL) {
            if (rem->current == 0) {
                remote = rem;
                break;
            }
            if (rem->current < remote->current) {
                remote = rem;
            }
            rem = rem->next;
        }
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CloudRouter set_hostandport: chose remote %p (first = %p)", remote, e->remote);
    }

    remote->current++;
    remote->total++;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CloudRouter set_hostandport: remote %p has %d current and %d total connections", remote, remote->current, remote->total);

    peer->inet_addr = remote->inet_addr;
    peer->port_n = remote->port_n;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "peer set from cache: %p", remote->inet_addr);
}

static ngx_int_t
ngx_http_cloudrouter_init_shm(ngx_shm_zone_t *shm_zone, void *data) {
    ngx_rbtree_node_t *sentinel;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    ngx_http_cloudrouter_shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    shm_zone->data = ngx_http_cloudrouter_shpool;

    sentinel = ngx_slab_alloc(ngx_http_cloudrouter_shpool, sizeof *sentinel);
    if (sentinel == NULL)
        return NGX_ERROR;

    ngx_http_cloudrouter_rbtree = ngx_slab_alloc(ngx_http_cloudrouter_shpool, sizeof *ngx_http_cloudrouter_rbtree);
    if (ngx_http_cloudrouter_rbtree == NULL)
        return NGX_ERROR;

    ngx_rbtree_init(ngx_http_cloudrouter_rbtree, sentinel, ngx_rbtree_insert_value);

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_init_cloud(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us) {
    int size;
    ngx_str_t *shm_name;

    us->peer.init = ngx_http_cloudrouter_init_upstream_peer;

    shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
    shm_name->len = sizeof("cloudrouter_cache");
    shm_name->data = (unsigned char *) "cloudrouter_cache";

    /* FIXME: make both constants configurable */
    size = NGX_HTTP_HS_CACHE_SIZE * sizeof(ngx_http_cloudrouter_node_t);
    /* assume ~ 8 remotes per entry */
    size += 8 * NGX_HTTP_HS_CACHE_SIZE * sizeof(ngx_http_cloudrouter_remote_t);
    size += 64*1024; /* slab structs */

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "CloudRouter requesting %d bytes of memory", size);

    ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf,
                                                     shm_name,
                                                     size,
                                                     &ngx_http_cloudrouter_module);

    if (shm_zone==NULL)
        return NGX_ERROR;

    shm_zone->init = ngx_http_cloudrouter_init_shm;

    return NGX_OK;
}

static ngx_int_t
ngx_http_cloudrouter_init_upstream_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us) {
    struct sockaddr_in* sin;
    ngx_http_hs_main_conf_t    *hscf;
    ngx_http_cloudrouter_peer_t *peer;
    hs_route_t *route;
    int tcb_s;

    hscf = ngx_http_get_module_main_conf(r, ngx_http_hs_module);
    if (hscf == NULL || hscf->tcb_route_db == NULL) {
        return NGX_ERROR;
    }

    peer = ngx_pcalloc(r->pool, sizeof(ngx_http_cloudrouter_peer_t));
    if (peer == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "NULL peer");
        return NGX_ERROR;
    }

    peer->route = NULL;

    peer->socklen = sizeof(struct sockaddr_in);
    peer->sockaddr = (struct sockaddr*)ngx_pcalloc(r->pool, peer->socklen);
    if (peer->sockaddr == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "ALERT: peer->sockaddr alloc failed");
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "init_peer");

    /* fallback = 404 host */
    ngx_str_set(&peer->name, "127.0.0.1");
    peer->inet_addr = ngx_inet_addr(peer->name.data, peer->name.len);
    peer->port_n = htons(8404);

    r->upstream->peer.data = peer;
    r->upstream->peer.free = ngx_http_cloudrouter_free_upstream_peer;
    r->upstream->peer.get = ngx_http_cloudrouter_get_upstream_peer;
    r->upstream->peer.tries = 1;

    // fetch config for client-supplied Host
    if (r->headers_in.server.len > 0) {
        route = (hs_route_t*)tcbdbget(hscf->tcb_route_db, r->headers_in.server.data, r->headers_in.server.len, &tcb_s);
    } else {
        route = NULL;
    }
    if (route == NULL) {
        // send user to 404 host
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CloudRouter: no route matched");
        return NGX_OK;
    } else {
        /* copy route into peer, managed memory */
        peer->route = ngx_pcalloc(r->pool, sizeof(hs_route_t));
        if (peer->route==NULL) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "ALERT: alloc failed");
            free(route);
            return NGX_ERROR;
        }
        (void)ngx_copy(peer->route, route, sizeof(hs_route_t));
        free(route); // gets malloc()'d by TC
        route = peer->route;

        peer->name.len = route->di_nlen;
        peer->name.data = ngx_pcalloc(r->pool, peer->name.len);
        (void)ngx_copy(peer->name.data, route->di_name, peer->name.len);

        ngx_shmtx_lock(&ngx_http_cloudrouter_shpool->mutex);

        ngx_http_cloudrouter_node_t *e = ngx_http_cloudrouter_get_locked(route);
        if (e && e->timestamp > (r->start_sec - NGX_HTTP_HS_CACHE_TIMEOUT)) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "cache hit");
            ngx_http_cloudrouter_remote_t *remote = e->remote;

            ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cached values READ: %p:%d:%s[%d],(%uxD,%d)", e, e->timestamp,
                           e->di_name,
                           e->di_nlen,
                           remote->inet_addr,
                           remote->port_n);

            ngx_http_cloudrouter_set_hostandport(r,peer,e);

            ngx_shmtx_unlock(&ngx_http_cloudrouter_shpool->mutex);
        } else {
            /* entry has expired.
             * pretend it does not exist, the preconnect handler will overwrite it.
             */

            int current = 0;
            if (e) {
                ngx_http_cloudrouter_remote_t *remote = e->remote;
                while (remote != NULL) {
                    current += remote->current;
                    remote = remote->next;
                }
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CloudRouter: cache entry expired");
            } else {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CloudRouter: no entry in cache");
            }
            ngx_shmtx_unlock(&ngx_http_cloudrouter_shpool->mutex);

            peer->sendbuf.data = ngx_pcalloc(r->pool, NGX_HTTP_CLOUDROUTER_PRECONNECT_SENDBUFSIZE);
            if (peer->sendbuf.data == NULL) {
                ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "alloc peer->sendbuf.data failed, aborting request");
                return NGX_ERROR;
            }

            peer->sendbuf.len = ngx_sprintf(peer->sendbuf.data, "BLNC %*s %ud", peer->route->di_nlen, peer->route->di_name, current) - peer->sendbuf.data;

            ngx_shmtx_unlock(&ngx_http_cloudrouter_shpool->mutex);

            r->upstream->peer.preconnect = (ngx_event_preconnect_pt)ngx_http_cloudrouter_peer_preconnect;
        }
        return NGX_OK;
    }
    /* never reached */
}

static ngx_int_t
ngx_http_cloudrouter_get_upstream_peer(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_http_cloudrouter_get_upstream_peer");
    ngx_http_cloudrouter_peer_t *peer = data;

    struct sockaddr_in* sin = (struct sockaddr_in*)peer->sockaddr;
    sin->sin_family = AF_INET;
    sin->sin_port = peer->port_n;
    sin->sin_addr.s_addr = peer->inet_addr;

    pc->cached = 0;
    pc->connection = NULL;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    return NGX_OK;
}

static void
ngx_http_cloudrouter_free_upstream_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_http_cloudrouter_free_upstream_peer state=%ud", state);
    ngx_http_cloudrouter_peer_t *peer = data;

    if (state == 0 && pc->tries == 0) {
        /* already freed */
        return;
    }

    // don't try again
    pc->tries = 0;

    if (peer->route == NULL) {
        /* 404 */
        return;
    }

    /* update stats */
    ngx_shmtx_lock(&ngx_http_cloudrouter_shpool->mutex);
    ngx_http_cloudrouter_node_t *e = ngx_http_cloudrouter_get_locked(peer->route);
    if (e == NULL) {
        ngx_shmtx_unlock(&ngx_http_cloudrouter_shpool->mutex);
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "CloudRouter free_upstream_peer: node is gone for this peer's route");
        return;
    }

    ngx_http_cloudrouter_remote_t *remote = e->remote;
    while (remote != NULL && remote->inet_addr != peer->inet_addr && remote->port_n != peer->port_n) {
        remote = remote->next;
    }
    if (remote != NULL) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "CloudRouter free_upstream_peer: remote has %d current and %d total connections", remote->current, remote->total);
        if (remote->current) {
            remote->current--;
        } else {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "CloudRouter free_upstream_peer: ERROR: current connections==0");
        }
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "CloudRouter free_upstream_peer: remote has now %d current and %d total connections", remote->current, remote->total);
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "CloudRouter free_upstream_peer: remote is gone");
    }

    ngx_shmtx_unlock(&ngx_http_cloudrouter_shpool->mutex);
}

static char *
ngx_http_cloudrouter_cmd_cloud(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_upstream_srv_conf_t  *uscf;
    ngx_str_t field, *value;

    value = cf->args->elts;
    field = value[1];

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    uscf->peer.init_upstream = ngx_http_upstream_init_cloud;
    uscf->flags = NGX_HTTP_UPSTREAM_CREATE | NGX_HTTP_UPSTREAM_BACKUP;

    return NGX_CONF_OK;
}

static void
ngx_http_cloudrouter_peer_preconnect_close(ngx_connection_t *c, ngx_http_cloudrouter_peer_preconnect_data_t *pcd, ngx_int_t status) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pcd->r->connection->log, 0, "preconnect_close %d", status);
    ngx_close_connection(c); c->destroyed = 1;
    pcd->r->main->count--;
    if (status==NGX_OK) {
        ngx_http_upstream_connect_real(pcd->r, pcd->u);
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, pcd->r->connection->log, 0,
                       "preconnect: ERROR");
        ngx_http_upstream_next(pcd->r,pcd->u,NGX_HTTP_UPSTREAM_FT_ERROR);
    }
    return;
}

static void
ngx_http_cloudrouter_peer_preconnect_write(ngx_event_t *wev) {
    ngx_connection_t *c;
    ngx_http_cloudrouter_peer_preconnect_data_t *pcd;
    ngx_http_upstream_t *u;
    ngx_http_request_t *r;
    ngx_http_cloudrouter_peer_t *peer;

    c = wev->data;
    pcd = c->data;

    r = pcd->r;
    u = pcd->u;

    if(wev->timedout) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "preconnect: write: timedout");
        return ngx_http_cloudrouter_peer_preconnect_close(c, pcd, NGX_ERROR);
    }

    if (pcd->done>0) {
        return;
    }

    if(r->main==NULL||r->request_complete||r->pool==NULL||r!=r->main) {
        ngx_close_connection(c); c->destroyed = 1;
        return;
    }

    peer = (ngx_http_cloudrouter_peer_t*)u->peer.data;

    if(pcd->sendbufpos < peer->sendbuf.len) {
        int n = ngx_send(c, peer->sendbuf.data + pcd->sendbufpos,
                         peer->sendbuf.len - pcd->sendbufpos);
        pcd->sendbufpos += n;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "preconnect: write: %d of %d", pcd->sendbufpos,
                       peer->sendbuf.len);
    }
}

static void
ngx_http_cloudrouter_peer_preconnect_read(ngx_event_t *rev) {
    ngx_connection_t    *c;
    ngx_http_cloudrouter_peer_preconnect_data_t *pcd;
    ngx_http_upstream_t *u;
    ngx_http_request_t  *r;
    int                 i;
    hs_route_t         *route;

    c   = rev->data;
    pcd = c->data;

    r   = pcd->r;
    u   = pcd->u;

    route = &pcd->route;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "preconnect: read");

    if (pcd->done>0) {
        return;
    }

    if (r->main==NULL||r->request_complete||r->pool==NULL||r!=r->main) {
        ngx_close_connection(c); c->destroyed = 1;
        return;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "cloudrouter preconnect server timed out");
        return ngx_http_cloudrouter_peer_preconnect_close(c, pcd, NGX_ERROR);
    }

    if (pcd->buf==NULL) {
        int size = sizeof(char)*1000;
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "creating buf");
        pcd->buf = ngx_pcalloc(r->pool, size);
        pcd->bufend = pcd->buf+size;
        pcd->bufpos = pcd->buf;

        if (pcd->buf==NULL) {
            ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ENOMEM,
                          "preconnect: read: could not allocate buf");
            return ngx_http_cloudrouter_peer_preconnect_close(c, pcd, NGX_ERROR);
        }
    }

    /*
     * Protocol format:
     * IP1\nPORT1\n
     * (optional) IPz\nPORTz\n
     * --
     */

    int bufsize = pcd->bufend - pcd->bufpos;
    ngx_int_t received;
    if (bufsize > 0) {
        received = ngx_recv(c, pcd->bufpos, bufsize);
    } else {
        received = 0;
    }

    if (received==NGX_AGAIN) {
        return;
    } else if (received>=0) {
        pcd->bufpos += received;

        for (i=0;i<(pcd->bufpos-pcd->buf);i++) {
            if (*(pcd->buf + i )=='-') {
                pcd->end_marker_count++;
            }
        }

        if (pcd->end_marker_count>=2) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "CloudRouter preconnect: message complete");

            ngx_http_cloudrouter_peer_t *peer = (ngx_http_cloudrouter_peer_t *)u->peer.data;
            unsigned char* next = pcd->buf;
            int new_node = 0;

            ngx_shmtx_lock(&ngx_http_cloudrouter_shpool->mutex);

            ngx_http_cloudrouter_node_t *e = ngx_http_cloudrouter_get_locked(route);
            if (e == NULL) {
                /* likely() */

                e = ngx_slab_alloc_locked(ngx_http_cloudrouter_shpool, sizeof *e);
                new_node = 1;

                e->node.key = ngx_http_cloudrouter_hash_route(route);

                (void)ngx_copy(e->di_name, route->di_name, sizeof(route->di_name));
                e->di_nlen = route->di_nlen;
            } else {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "CloudRouter preconnect: reusing existing node");
            }

            e->timestamp = time(NULL);
            ngx_http_cloudrouter_clear_remotes_locked(e, rev->log);

            while (next < pcd->bufpos) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "CloudRouter preconnect: parsing message");

                unsigned char *ip = NULL;
                unsigned char *port = NULL;
                ip = next;
                while (++next < pcd->bufpos) {
                    if (*(next-1) == '\n') {
                        if (ip && port)
                            break;
                        port = next;
                    }
                }

                if (ip && port) {
                    ngx_http_cloudrouter_remote_t *remote = ngx_http_cloudrouter_add_remote_locked(e);

                    int iplen = port-ip-1;
                    iplen = iplen > 16 ? 16 : iplen;

                    remote->inet_addr = ngx_inet_addr(ip, iplen);
                    if (remote->inet_addr == INADDR_NONE) {
                        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_EINVAL,
                                      "CloudRouter preconnect: IP address from Agent invalid for route %s",
                                      e->di_name);
                        goto failure;
                    }

                    int portlen = next-port-1;
                    remote->port_n = htons(ngx_atoi(port,portlen));

                    ngx_log_debug7(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                                   "CloudRouter preconnect: cached values SET: e=%p rem=%p ts=%d %s[%d] %uxD:%d",
                                   e, remote, e->timestamp,
                                   e->di_name, e->di_nlen,
                                   remote->inet_addr, remote->port_n);
                }
            }

            if (!e->remote) {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                              "CloudRouter preconnect: Agent sent no remotes");
                goto failure;
            }

            ngx_http_cloudrouter_set_hostandport(r, peer, e);
            if (new_node) {
                ngx_rbtree_insert(ngx_http_cloudrouter_rbtree, &e->node);
            }
            ngx_shmtx_unlock(&ngx_http_cloudrouter_shpool->mutex);
            return ngx_http_cloudrouter_peer_preconnect_close(c, pcd, NGX_OK);

failure:
            if (!new_node) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pcd->r->connection->log, 0, "peer_preconnect_read: calling rbtree_delete");
                ngx_rbtree_delete(ngx_http_cloudrouter_rbtree, &e->node);
            }
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pcd->r->connection->log, 0, "peer_preconnect_read: calling free_node_locked");
            ngx_http_cloudrouter_free_node_locked(e, rev->log);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pcd->r->connection->log, 0, "peer_preconnect_read: calling shmtx_unlock");
            ngx_shmtx_unlock(&ngx_http_cloudrouter_shpool->mutex);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pcd->r->connection->log, 0, "peer_preconnect_read: calling peer_preconnect_close");
            return ngx_http_cloudrouter_peer_preconnect_close(c, pcd, NGX_ERROR);
        }
        return;
    }

    /* unknown error condition from ngx_recv */
    return;
}

void
ngx_http_cloudrouter_preconnect_cleanup(void *data) {
    ngx_http_cloudrouter_peer_preconnect_data_t *pcd = data;

    if (!pcd->c->destroyed) {
        ngx_close_connection(pcd->c);
        pcd->c->destroyed = 1;
    }
    pcd->done=1;
}

void
ngx_http_cloudrouter_peer_preconnect(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    ngx_int_t rc;
    ngx_peer_connection_t *c;
    struct sockaddr_in *sin;
    ngx_http_cloudrouter_peer_preconnect_data_t *pcd;
    ngx_http_cleanup_t *cln;
    ngx_http_cloudrouter_peer_t *peer;

    r->connection->log->action = "connecting to cloudrouter agent";

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "preconnect");

    c = ngx_pcalloc(r->connection->pool, sizeof(ngx_peer_connection_t));
    sin = ngx_pcalloc(r->connection->pool, sizeof(struct sockaddr_in));
    pcd = ngx_pcalloc(r->connection->pool, sizeof(ngx_http_cloudrouter_peer_preconnect_data_t));
    peer = (ngx_http_cloudrouter_peer_t*)u->peer.data;

    if (sin==NULL || c==NULL || pcd==NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "preconnect: cannot allocate sin/c/pcd");
        return;
    }

    /* FIXME: should cache this */
    sin->sin_family = AF_INET;
    sin->sin_port = htons(9091);
    ngx_str_t localhost;
    ngx_str_set(&localhost, "127.0.0.1");
    sin->sin_addr.s_addr = ngx_inet_addr(localhost.data, localhost.len);

    c->sockaddr = (struct sockaddr *)sin;
    c->socklen = sizeof(struct sockaddr_in);
    c->get = ngx_event_get_peer; // dummy method returning the peer itself.
    c->log = r->connection->log;
    c->log_error = r->connection->log_error;
    c->name = ngx_pcalloc(r->connection->pool, sizeof *c->name);
    if (c->name == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "preconnect: cannot allocate c->name");
        return;
    }
    ngx_str_set(c->name, "127.0.0.1:9091");

    rc = ngx_event_connect_peer(c);
    if (rc==NGX_ERROR || rc==NGX_BUSY || rc==NGX_DECLINED) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "preconnect very much unsuccessful.");
        if (c->connection) {
            ngx_close_connection(c->connection); c->connection->destroyed = 1;
        }
        ngx_http_upstream_next(r,u,NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    r->main->count++;

    pcd->r = r;
    pcd->u = u;
    pcd->sendbufpos = 0;
    if (peer->route==NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ROUTE is null in preconnect!");
        ngx_log_debug(NGX_LOG_ERR, r->connection->log, 0,
                      "ROUTE is null in preconnect!");
        ngx_http_upstream_next(r,u,NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }
    (void)ngx_copy(&pcd->route,peer->route, sizeof(hs_route_t));
    pcd->c = c->connection;

    c->connection->data = pcd;
    c->connection->pool = r->connection->pool;

    c->connection->read->handler = ngx_http_cloudrouter_peer_preconnect_read;
    c->connection->write->handler = ngx_http_cloudrouter_peer_preconnect_write;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "preconnect successful.");

    ngx_add_timer(c->connection->read, 10000);
    ngx_add_timer(c->connection->write, 10000);

    cln = ngx_http_cleanup_add(r, 0);
    cln->data = pcd;
    cln->handler = ngx_http_cloudrouter_preconnect_cleanup;
}
