#include "getaddrinfo_a.h"

int gai_error(struct gaicb *req)
{
  return req->__return;
}
int gai_cancel(struct gaicb *gaicbp)
{
	return 0;
}
