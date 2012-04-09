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
  ngx_http_hs_tcdata_t tcd;
  bool rc;
  TCBDB* bdb = tcbdbnew();
  if (!tcbdbopen(bdb, "cloud.tcb", BDBOWRITER | BDBOCREAT)) {
    printf("failed to open hs db\n");
    return 2;
  }

  strcpy(tcd.primary_agent_ip_strbuf, argv[2]);
  strcpy(tcd.secondary_agent_ip_strbuf, argv[3]);
  strcpy(tcd.app_id_token_strbuf, argv[4]);
  tcd.primary_agent_ip_strsize = strlen(argv[2]);
  tcd.secondary_agent_ip_strsize = strlen(argv[3]);
  tcd.app_id_token_strsize = strlen(argv[4]);

  printf("'%s' '%s' '%s'\n", argv[2], argv[3], argv[4]);
  printf("'%s' '%s' '%s'\n", tcd.primary_agent_ip_strbuf, tcd.secondary_agent_ip_strbuf, tcd.app_id_token_strbuf);

  rc = tcbdbput(bdb, argv[1], strlen(argv[1]), &tcd, sizeof(ngx_http_hs_tcdata_t));
  tcbdbclose(bdb);

  if (rc == true)
    return 0;
  else
    return 1;
}
