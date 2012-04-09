#include <stdlib.h>
#include <stdio.h>
#include <tcutil.h>
#include <tcbdb.h>
#include <string.h>

typedef struct {
    size_t primary_agent_ip_strsize;
    u_char primary_agent_ip_strbuf[16];
    size_t secondary_agent_ip_strsize;
    u_char secondary_agent_ip_strbuf[16];
    size_t app_id_token_strsize;
    u_char app_id_token_strbuf[64];
} ngx_http_hs_tcdata_t;

int main(int argc, char* argv[]) {
  ngx_http_hs_tcdata_t *tcd;
  bool rc;
  int tcb_s;
  TCBDB* bdb = tcbdbnew();
  if (!tcbdbopen(bdb, "cloud.tcb", BDBOREADER)) {
    printf("failed to open hs db\n");
    return 2;
  }

  tcd = (ngx_http_hs_tcdata_t*)tcbdbget(bdb, argv[1], strlen(argv[1]), &tcb_s);
  printf("'%s' '%s' '%s'\n", tcd->primary_agent_ip_strbuf, tcd->secondary_agent_ip_strbuf, tcd->app_id_token_strbuf);

  tcbdbclose(bdb);
}
