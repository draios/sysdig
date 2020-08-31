#pragma once

#ifdef MUSL_OPTIMIZED
#define GAI_NOWAIT 1

/* Structure used as control block for asynchronous lookup.  */
struct gaicb
{
  const char *ar_name;		/* Name to look up.  */
  const char *ar_service;	/* Service name.  */
  const struct addrinfo *ar_request; /* Additional request specification.  */
  struct addrinfo *ar_result;	/* Pointer to result.  */
  /* The following are internal elements.  */
  int __return;
  int __glibc_reserved[5];
};

int gai_error(struct gaicb *req);

int gai_cancel(struct gaicb *gaicbp);

// This is just a placeholder for now, we need to do it in an asynchronous way like it is in glibc
#define getaddrinfo_a(M, L, N, S) getaddrinfo(NULL, L[0]->ar_service, L[0]->ar_request, &L[0]->ar_result)
#endif
