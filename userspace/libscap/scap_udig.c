#ifndef _WIN32
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include "scap.h"

#include <pthread.h>
#include <sys/socket.h>
#include <linux/un.h>

#include "scap-int.h"
#include "../../driver/ppm_ringbuffer.h"

#define PPM_PORT_STATSD 8125

// needed for memfd_create it can be included using linux/memfd.h
// but there are no guarantees it exists on older kernels.
#define PPM_MFD_CLOEXEC	0x0001U

#ifndef UDIG_INSTRUMENTER
#ifndef UDIG
static void udig_server_thread(scap_t *handle)
{
	pthread_exit(udig_fd_server(&(handle->m_devs[0].m_bufinfo_fd), &(handle->m_devs[0].m_fd)));
}
#endif
// udig_receive_fd is the action used to ask
// the udig_fd_server for file descriptors relative to ring buffers
static int udig_receive_fd(int conn, int* ring_fd, int* ring_desc_fd)
{
	struct mmsghdr msgh[2];
	struct iovec iov;
	union
	{
		struct cmsghdr cmsgh;
		char   control[CMSG_SPACE(sizeof(int))];
	} control_ring_fd;
	union
	{
		struct cmsghdr cmsgh;
		char   control[CMSG_SPACE(sizeof(int))];
	} control_ring_desc_fd;
	struct cmsghdr *cmsgh0;
	struct cmsghdr *cmsgh1;

	/* we need to send some placeholder data for the message to be sent */
	char placeholder;
	iov.iov_base = &placeholder;
	iov.iov_len = sizeof(char);

	// message header for ring_fd
	msgh[0].msg_hdr.msg_name = NULL;
	msgh[0].msg_hdr.msg_namelen = 0;
	msgh[0].msg_hdr.msg_iov = &iov;
	msgh[0].msg_hdr.msg_iovlen = 1;
	msgh[0].msg_hdr.msg_control = control_ring_fd.control;
	msgh[0].msg_hdr.msg_controllen = sizeof(control_ring_fd.control);

	// message header for ring_desc_fd
	msgh[1].msg_hdr.msg_name = NULL;
	msgh[1].msg_hdr.msg_namelen = 0;
	msgh[1].msg_hdr.msg_iov = &iov;
	msgh[1].msg_hdr.msg_iovlen = 1;
	msgh[1].msg_hdr.msg_control = control_ring_desc_fd.control;
	msgh[1].msg_hdr.msg_controllen = sizeof(control_ring_desc_fd.control);

	int retval = recvmmsg(conn, msgh, 2, 0, NULL);
	if(retval == -1)
	{
		return SCAP_FAILURE;
	}

	cmsgh0 = CMSG_FIRSTHDR(&msgh[0].msg_hdr);
	if(!cmsgh0)
	{
		return SCAP_FAILURE;
	}

	if(cmsgh0->cmsg_level != SOL_SOCKET)
	{
		return SCAP_FAILURE;
	}
	if(cmsgh0->cmsg_type != SCM_RIGHTS)
	{
		return SCAP_FAILURE;
	}

	cmsgh1 = CMSG_FIRSTHDR(&msgh[1].msg_hdr);
	if(!cmsgh1)
	{
		return SCAP_FAILURE;
	}

	if(cmsgh1->cmsg_level != SOL_SOCKET)
	{
		return SCAP_FAILURE;
	}
	if(cmsgh1->cmsg_type != SCM_RIGHTS)
	{
		return SCAP_FAILURE;
	}

	if(ring_fd != NULL)
	{
		*ring_fd = *((int *) CMSG_DATA(cmsgh0));
	}
	if(ring_desc_fd != NULL)
	{
		*ring_desc_fd = *((int *) CMSG_DATA(cmsgh1));
	}

	return SCAP_SUCCESS;
}

// udig_server_connect is used by producers
// to connect to the udig socket exposed by consumers.
static int udig_server_connect()
{
	int conn, ret;
	struct sockaddr_un address;

	conn = socket(PF_UNIX, SOCK_STREAM, 0);
	if(conn == -1)
	{
		return SCAP_FAILURE;
	}

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, UNIX_PATH_MAX, UDIG_RING_CTRL_SOCKET_PATH);

	ret = connect(conn, (struct sockaddr *)&address, sizeof(struct sockaddr_un));
	if(ret != 0)
	{
		return SCAP_FAILURE;
	}

	return conn;
}

// udig_receive_ring_fd populates the passed
// ring_fd witht the ring_fd descriptor.
// The ring_fd descriptor is taken from the consumer by
// conneting to it via the unix socket.
static int udig_receive_ring_fd(int* ring_fd)
{
	int conn = udig_server_connect();
	if(conn == SCAP_FAILURE)
	{
		return SCAP_FAILURE;
	}
	int res = udig_receive_fd(conn, ring_fd, NULL);
	if(res == SCAP_FAILURE)
	{
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}

// udig_receive_ring_desc_fd populates the passed
// ring_fd witht the ring_desc_fd descriptor.
// The ring_fd descriptor is taken from the consumer by
// conneting to it via the unix socket.
static int udig_receive_ring_desc_fd(int* ring_desc_fd)
{
	int conn = udig_server_connect();
	if(conn == SCAP_FAILURE)
	{
		return SCAP_FAILURE;
	}
	int res = udig_receive_fd(conn, NULL, ring_desc_fd);
	if(res == SCAP_FAILURE)
	{
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}

// udig_send_fds is in charge of sending the file descriptors
// to an accepted connection that happens when a producer asks for them.
static int udig_send_fds(int conn, int ring_fd, int ring_desc_fd)
{
	// we hold two messages
	// msgh[0] is for ring_fd
	// msgh[1] is for ring_desc_fd
	struct mmsghdr msgh[2];
	struct iovec iov;
	union
	{
		struct cmsghdr cmsgh;
		char control[CMSG_SPACE(sizeof(int))];
	} control_ring_fd;
	union
	{
		struct cmsghdr cmsgh;
		char control[CMSG_SPACE(sizeof(int))];
	} control_ring_desc_fd;

	if(ring_fd == -1)
	{
		fprintf(stderr, "udig_send_fds: ring_fd is not valid\n");
		return SCAP_FAILURE;
	}
	if(ring_desc_fd == -1)
	{
		fprintf(stderr, "udig_send_fds: ring_desc_fd is not valid\n");
		return SCAP_FAILURE;
	}

	// we need to send some placeholder data for the message to be sent
	char placeholder = 'A';
	iov.iov_base = &placeholder;
	iov.iov_len = sizeof(char);

	// message for ring_fd
	msgh[0].msg_hdr.msg_name = NULL;
	msgh[0].msg_hdr.msg_namelen = 0;
	msgh[0].msg_hdr.msg_iov = &iov;
	msgh[0].msg_hdr.msg_iovlen = 1;
	msgh[0].msg_hdr.msg_control = control_ring_fd.control;
	msgh[0].msg_hdr.msg_controllen = sizeof(control_ring_fd.control);

	// message for ring_desc_fd
	msgh[1].msg_hdr.msg_name = NULL;
	msgh[1].msg_hdr.msg_namelen = 0;
	msgh[1].msg_hdr.msg_iov = &iov;
	msgh[1].msg_hdr.msg_iovlen = 1;
	msgh[1].msg_hdr.msg_control = control_ring_desc_fd.control;
	msgh[1].msg_hdr.msg_controllen = sizeof(control_ring_desc_fd.control);

	// append the ring_fd file descriptor
	control_ring_fd.cmsgh.cmsg_len = CMSG_LEN(sizeof(int));
	control_ring_fd.cmsgh.cmsg_level = SOL_SOCKET;
	control_ring_fd.cmsgh.cmsg_type = SCM_RIGHTS;

	// append the ring_desc_fd file descriptor
	control_ring_desc_fd.cmsgh.cmsg_len = CMSG_LEN(sizeof(int));
	control_ring_desc_fd.cmsgh.cmsg_level = SOL_SOCKET;
	control_ring_desc_fd.cmsgh.cmsg_type = SCM_RIGHTS;

	*((int *) CMSG_DATA(CMSG_FIRSTHDR(&msgh[0].msg_hdr))) = ring_fd;
	*((int *) CMSG_DATA(CMSG_FIRSTHDR(&msgh[1].msg_hdr))) = ring_desc_fd;

	int size = sendmmsg(conn, msgh, 2, 0);
	if(size < 0)
	{
		fprintf(stderr, "udig_send_fds: error: %s\n", strerror(errno));
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}

// udig_fd_server is the server used by the consumer
// to create the socket and listen for new producers to
// receive the file descriptors.
// The server only passes file descriptors around,
// once the file descriptors are passed they are
// available to the producers until the consumer is stopped.
int32_t udig_fd_server(int* ring_descs_fd, int* ring_fd)
{
	int sock, conn, ret;
	struct sockaddr_un address;
	socklen_t addrlen;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if(sock == -1)
	{
		fprintf(stderr, "udig_fd_server: error registering unix socket: %s\n", strerror(errno));
		return SCAP_FAILURE;
	}

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, UNIX_PATH_MAX, UDIG_RING_CTRL_SOCKET_PATH);

	ret = unlink(UDIG_RING_CTRL_SOCKET_PATH);
	if(ret != 0 && ret != -ENOENT && ret != -EPERM)
	{
		fprintf(stderr, "udig_fd_server: error unlinking unix socket: %s\n", strerror(errno));
		return SCAP_FAILURE;
	}

	ret = bind(sock, (struct sockaddr *) &address, sizeof(address));
	if(ret != 0)
	{
		fprintf(stderr, "udig_fd_server: error binding unix socket: %s\n", strerror(errno));
		return SCAP_FAILURE;
	}

	ret = listen(sock, UDIG_RING_CTRL_SOCKET_CONNECT_BACKLOG);
	if(ret != 0)
	{
		fprintf(stderr, "udig_fd_server: error on listen: %s\n", strerror(errno));
		return SCAP_FAILURE;
	}

	int connect_attempts_left = UDIG_RING_CTRL_CONNECT_MAX_ATTEMPTS;
	while(true)
	{
		conn = accept(sock, (struct sockaddr *) &address, &addrlen);
		if(conn == -1)
		{
			fprintf(stderr, "udig_fd_server: accept error: %s\n", strerror(errno));
			close(conn);
			--connect_attempts_left;
			if(connect_attempts_left <=  0) {
				fprintf(
					stderr,
					"udig_fd_server: no more connect attempts left, shitting down the sockets server to connect new userspace producers, existing producers will still be able to work.\n"
				);
				return SCAP_FAILURE;
			}
			continue;
		}
		udig_send_fds(conn, *ring_fd, *ring_descs_fd);
		close(conn);
		connect_attempts_left = UDIG_RING_CTRL_CONNECT_MAX_ATTEMPTS;
	}
}

int udig_memfd_shm_open(const char *__name, int __oflag, mode_t __mode)
{
	int fd = -1;
	// creation is only available to the consumer implementation
	// event producers can't create the ring buffers.
#ifndef UDIG
	if(__oflag & O_CREAT)
	{
		fd = syscall(__NR_memfd_create, __name, (unsigned int)(PPM_MFD_CLOEXEC));
		if(fd < 0)
		{
			return shm_open(__name, __oflag, __mode);
		}
		return fd;
	} 
#endif
	int ret = -1;
	// If we are a producer, we want to go get the file descriptor to use it
	if(__name ==  (const char*)UDIG_RING_SM_FNAME)
	{
		ret = udig_receive_ring_fd(&fd);
	}
	if(__name == (const char*)UDIG_RING_DESCS_SM_FNAME)
	{
		ret = udig_receive_ring_desc_fd(&fd);
	}
	if(ret == SCAP_FAILURE) {
		return -1;
	}
	return fd;
}

int udig_memfd_shm_unlink(const char *name)
{
	if(access(name, F_OK ) != -1 ) {
		return shm_unlink(name);
	}
	return 0;
}

#define ud_shm_open udig_memfd_shm_open
#define ud_shm_unlink udig_memfd_shm_unlink
#else
int ud_shm_open(const char *name, int flag, mode_t mode);
int ud_shm_unlink(const char *name);
#endif


///////////////////////////////////////////////////////////////////////////////
// The following 2 function map the ring buffer and the ring buffer 
// descriptors into the address space of this process.
// This is the buffer that will be consumed by scap.
///////////////////////////////////////////////////////////////////////////////
int32_t udig_alloc_ring(int* ring_fd, 
	uint8_t** ring, 
	uint32_t *ringsize,
	char *error)
{
	//
	// First, try to open an existing ring
	//
	*ring_fd = ud_shm_open(UDIG_RING_SM_FNAME, O_RDWR, 0);
	if(*ring_fd >= 0)
	{
		//
		// Existing ring found, find out the size
		//
		struct stat rstat;
		if(fstat(*ring_fd, &rstat) < 0)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring fstat error: %s\n", strerror(errno));
			return SCAP_FAILURE;
		}

		*ringsize = (uint32_t)rstat.st_size;
	}
	else
	{
		//
		// No ring found, allocate a new one.
		// Note that, according to the man page, the content of the buffer will
		// be initialized to 0.
		//
		*ringsize = UDIG_RING_SIZE;

		*ring_fd = ud_shm_open(UDIG_RING_SM_FNAME, O_CREAT | O_RDWR, 
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if(*ring_fd >= 0)
		{
			//
			// For some reason, shm_open doesn't always set the write flag for
			// 'group' and 'other'. Fix it here.
			//
			fchmod(*ring_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

			if(ftruncate(*ring_fd, *ringsize) < 0)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring ftruncate error: %s\n", strerror(errno));
				close(*ring_fd);
				return SCAP_FAILURE;
			}
		}
		else
		{
			snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring shm_open error: %s\n", strerror(errno));
			return SCAP_FAILURE;
		}
	}

	//
	// Map the ring. This is a multi-step process because we want to map two
	// consecutive copies of the same memory to reuse the driver fillers, which
	// expect to be able to go past the end of the ring.
	// First of all, allocate enough space for the 2 copies. This allows us 
	// to find an area of consecutive memory that is big enough.
	//
	uint8_t* buf1 = (uint8_t*)mmap(NULL, (*ringsize) * 2, 
		PROT_WRITE, MAP_SHARED,
		*ring_fd, 0);
	if(buf1 == MAP_FAILED)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map double buffer\n");
		close(*ring_fd);
		return SCAP_FAILURE;
	}

	// Now that we have the address, unmap the double-lenght buffer so we can 
	// use the two halves.
	munmap(buf1, (*ringsize) * 2);

	// Map the first ring copy at exactly the beginning of the previously
	// allocated area, forcing it with MAP_FIXED.
	*ring = (uint8_t*)mmap(buf1, *ringsize, 
		PROT_WRITE, MAP_SHARED | MAP_FIXED, *ring_fd, 0);
	if(*ring != buf1)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring mmap 2 error: %s\n", strerror(errno));
		close(*ring_fd);
		return SCAP_FAILURE;
	}

	// Map the second ring copy just after the end of the first one.
	uint8_t* buf2 = buf1 + *ringsize;
	uint8_t* ring2 = (uint8_t*)mmap(buf2, *ringsize, 
		PROT_WRITE, MAP_SHARED | MAP_FIXED, *ring_fd, 0);
	if(ring2 != buf2)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map second copy of buffer, needed %p, obtained %p, base=%p\n", 
			buf2, ring2, buf1);
		close(*ring_fd);
		munmap(*ring, *ringsize);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t udig_alloc_ring_descriptors(int* ring_descs_fd, 
	struct ppm_ring_buffer_info** ring_info, 
	struct udig_ring_buffer_status** ring_status,
	char *error)
{
	uint32_t mem_size = sizeof(struct ppm_ring_buffer_info) + sizeof(struct udig_ring_buffer_status);

	//
	// First, try to open an existing ring
	//
	*ring_descs_fd = ud_shm_open(UDIG_RING_DESCS_SM_FNAME, O_RDWR, 0);
	if(*ring_descs_fd < 0)
	{
		//
		// No existing ring file found in /dev/shm, create a new one.
		//
		*ring_descs_fd = ud_shm_open(UDIG_RING_DESCS_SM_FNAME, O_CREAT | O_RDWR | O_EXCL, 
				S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if(*ring_descs_fd >= 0)
		{
			//
			// For some reason, shm_open doesn't always set the write flag for
			// 'group' and 'other'. Fix it here.
			//
			fchmod(*ring_descs_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

			//
			// Ring created, set its size
			//
			if(ftruncate(*ring_descs_fd, mem_size) < 0)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring_descriptors ftruncate error: %s\n", strerror(errno));
				close(*ring_descs_fd);
				ud_shm_unlink(UDIG_RING_DESCS_SM_FNAME);
				return SCAP_FAILURE;
			}
		}
		else
		{
			snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring_descriptors shm_open error: %s\n", strerror(errno));
			ud_shm_unlink(UDIG_RING_DESCS_SM_FNAME);
			return SCAP_FAILURE;
		}
	}

	//
	// Map the memory
	//
	uint8_t* descs = (uint8_t*)mmap(NULL, mem_size, PROT_READ|PROT_WRITE, MAP_SHARED, 
		*ring_descs_fd, 0);
	if(descs == MAP_FAILED)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map descriptors\n");
		close(*ring_descs_fd);
		return SCAP_FAILURE;
	}

	*ring_info = (struct ppm_ring_buffer_info*)descs;

	//
	// Locate the ring buffer status object
	//
	*ring_status = (struct udig_ring_buffer_status*)((uint64_t)*ring_info + 
		sizeof(struct ppm_ring_buffer_info));

	//
	// If we are the original creators of the shared buffer, proceed to
	// initialize it.
	// Note that, according to the man page of ud_shm_open, we are guaranteed that 
	// the content of the buffer will initiually be initialized to 0.
	//
	if(__sync_bool_compare_and_swap(&((*ring_status)->m_initialized), 0, 1))
	{
		(*ring_status)->m_buffer_lock = 0;
		(*ring_status)->m_capturing_pid = 0;
		(*ring_status)->m_stopped = 0;
		(*ring_status)->m_last_print_time.tv_sec = 0;
		(*ring_status)->m_last_print_time.tv_nsec = 0;
	}

	return SCAP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// These 2 function free the ring buffer and the ring buffer descriptors.
///////////////////////////////////////////////////////////////////////////////
void udig_free_ring(uint8_t* addr, uint32_t size)
{
	munmap(addr, size / 2);
	munmap(addr + size / 2, size / 2);
}

void udig_free_ring_descriptors(uint8_t* addr)
{
	uint32_t mem_size = sizeof(struct ppm_ring_buffer_info) + sizeof(struct udig_ring_buffer_status);
	munmap(addr, mem_size);
}

///////////////////////////////////////////////////////////////////////////////
// Capture control helpers.
///////////////////////////////////////////////////////////////////////////////
bool acquire_and_init_ring_status_buffer(scap_t* handle)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	bool res = __sync_bool_compare_and_swap(&(rbs->m_capturing_pid), 0, getpid());

	if(res)
	{
		//
		// Initialize the ring
		//
		rbs->m_stopped = 0;
		rbs->m_last_print_time.tv_sec = 0;
		rbs->m_last_print_time.tv_nsec = 0;

		//
		// Initialize the consumer
		//
		struct udig_consumer_t* consumer = &(rbs->m_consumer);

		memset(consumer, 0, sizeof(struct udig_consumer_t));
		consumer->dropping_mode = 0;
		consumer->snaplen = RW_SNAPLEN;
		consumer->sampling_ratio = 1;
		consumer->sampling_interval = 0;
		consumer->is_dropping = 0;
		consumer->do_dynamic_snaplen = false;
		consumer->need_to_insert_drop_e = 0;
		consumer->need_to_insert_drop_x = 0;
		consumer->fullcapture_port_range_start = 0;
		consumer->fullcapture_port_range_end = 0;
		consumer->statsd_port = PPM_PORT_STATSD;
	}

	return res;
}

int32_t udig_begin_capture(scap_t* handle, char *error)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;

	if(rbs->m_capturing_pid != 0)
	{
		//
		// Looks like there is already a consumer, but ther variable might still
		// be set by a previous crashed consumer. To understand that, we check if
		// there is an alive process with that pid. If not, we reset the variable.
		//
		char fbuf[48];
		snprintf(fbuf, sizeof(fbuf), "/proc/%d", rbs->m_capturing_pid);
		FILE* f = fopen(fbuf, "r");
		if(f == NULL)
		{
			rbs->m_capturing_pid = 0;
		}
		else
		{
			fclose(f);
			snprintf(error, SCAP_LASTERR_SIZE, "another udig capture is already active");
			return SCAP_FAILURE;
		}
	}

#if !defined(UDIG) && !defined(UDIG_INSTRUMENTER)
	pthread_t thread;
	int trc = pthread_create(&thread, NULL, udig_server_thread, (void *)handle);
	if (trc)
	{
		return SCAP_FAILURE;
	}
#endif

	struct ppm_ring_buffer_info* rbi = handle->m_devs[0].m_bufinfo;
	rbi->head = 0;
	rbi->tail = 0;
	rbi->n_evts = 0;
	rbi->n_drops_buffer = 0;

	if(acquire_and_init_ring_status_buffer(handle))
	{
		handle->m_udig_capturing = true;
		return SCAP_SUCCESS;
	}
	else
	{
		snprintf(error, SCAP_LASTERR_SIZE, "cannot start the capture");
		return SCAP_FAILURE;
	}
}

void udig_start_capture(scap_t* handle)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	rbs->m_stopped = 0;
}

void udig_stop_capture(scap_t* handle)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	rbs->m_stopped = 1;
}

void udig_end_capture(scap_t* handle)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	if(handle->m_udig_capturing)
	{
		//__sync_bool_compare_and_swap(&(rbs->m_capturing_pid), getpid(), 0);
		rbs->m_capturing_pid = 0;
	}
}

uint32_t udig_set_snaplen(scap_t* handle, uint32_t snaplen)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	rbs->m_consumer.snaplen = snaplen;
	return SCAP_SUCCESS;
}

int32_t udig_stop_dropping_mode(scap_t* handle)
{
	struct udig_consumer_t* consumer = &(handle->m_devs[0].m_bufstatus->m_consumer);
	consumer->dropping_mode = 0;
	consumer->sampling_interval = 1000000000;
	consumer->sampling_ratio = 1;

	return SCAP_SUCCESS;
}

int32_t udig_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio)
{
	struct udig_consumer_t* consumer = &(handle->m_devs[0].m_bufstatus->m_consumer);

	consumer->dropping_mode = 1;

	if(sampling_ratio != 1 &&
		sampling_ratio != 2 &&
		sampling_ratio != 4 &&
		sampling_ratio != 8 &&
		sampling_ratio != 16 &&
		sampling_ratio != 32 &&
		sampling_ratio != 64 &&
		sampling_ratio != 128) 
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid sampling ratio %u\n", sampling_ratio);
		return SCAP_FAILURE;
	}

	consumer->sampling_interval = 1000000000 / sampling_ratio;
	consumer->sampling_ratio = sampling_ratio;

	return SCAP_SUCCESS;
}

#endif // _WIN32
