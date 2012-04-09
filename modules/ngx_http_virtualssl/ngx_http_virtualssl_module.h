#ifndef _NGX_HTTP_VIRTUALSSL_H_INCLUDED_
#define _NGX_HTTP_VIRTUALSSL_H_INCLUDED_
int ngx_http_virtualssl_handle_sni(ngx_ssl_conn_t *ssl_conn, u_char *host, size_t len);
#endif

