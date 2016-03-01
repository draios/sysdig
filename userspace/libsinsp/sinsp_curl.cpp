//
// sinsp_curl.h
//
// Curl utility
//

#if defined(__linux__)

#include "sinsp_curl.h"
#include <fstream>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

sinsp_curl::data sinsp_curl::m_config;

sinsp_curl::sinsp_curl(const std::string& uristr, long timeout_ms):
	m_curl(curl_easy_init()), m_uri(uristr), m_timeout_ms(timeout_ms)

{
	init();
}

sinsp_curl::sinsp_curl(const uri& url, long timeout_ms):
	m_curl(curl_easy_init()), m_uri(url), m_timeout_ms(timeout_ms)
{
	init();
}

sinsp_curl::sinsp_curl(const std::string& uristr,
	const std::string& cert, const std::string& key, const std::string& key_passphrase,
	const std::string& ca_cert, bool verify_peer, const std::string& cert_type,
	const std::string& bearer_token,
	long timeout_ms):
		m_curl(curl_easy_init()), m_uri(uristr), m_timeout_ms(timeout_ms),
		m_ssl(new ssl(cert, key, key_passphrase, ca_cert, verify_peer, cert_type, bearer_token))
{
	init_ssl();
}

sinsp_curl::sinsp_curl(const uri& url,
	const std::string& cert, const std::string& key, const std::string& key_passphrase,
	const std::string& ca_cert, bool verify_peer, const std::string& cert_type,
	const std::string& bearer_token,
	long timeout_ms):
		m_curl(curl_easy_init()), m_uri(url), m_timeout_ms(timeout_ms),
		m_ssl(new ssl(cert, key, key_passphrase, ca_cert, verify_peer, cert_type, bearer_token))
{
	init_ssl();
}

sinsp_curl::sinsp_curl(const std::string& uristr, ssl::ptr_t p_ssl, long timeout_ms):
		m_curl(curl_easy_init()), m_uri(uristr), m_timeout_ms(timeout_ms),
		m_ssl(p_ssl)
{
	init_ssl();
}

sinsp_curl::sinsp_curl(const uri& url, ssl::ptr_t p_ssl, long timeout_ms):
		m_curl(curl_easy_init()), m_uri(url), m_timeout_ms(timeout_ms),
		m_ssl(p_ssl)
{
	init_ssl();
}

void sinsp_curl::init()
{
	if(!m_curl)
	{
		throw sinsp_exception("Cannot initialize CURL.");
	}

	check_error(curl_easy_setopt(m_curl, CURLOPT_FORBID_REUSE, 1L));
	curl_easy_setopt(m_curl, CURLOPT_DEBUGFUNCTION, &sinsp_curl::trace);
	curl_easy_setopt(m_curl, CURLOPT_DEBUGDATA, &m_config);
	m_config.trace_ascii = 0; // set to 1 for ascii printout
	// the DEBUGFUNCTION has no effect without VERBOSE set to 1
	curl_easy_setopt(m_curl, CURLOPT_VERBOSE, 0L);
}

sinsp_curl::~sinsp_curl()
{
	curl_easy_cleanup(m_curl);
}

void sinsp_curl::init_ssl(CURL* curl, ssl::ptr_t ssl_data)
{
	if(curl && ssl_data)
	{
		if(!ssl_data->cert().empty())
		{
			check_error(curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, ssl_data->cert_type().c_str()));
			check_error(curl_easy_setopt(curl, CURLOPT_SSLCERT, ssl_data->cert().c_str()));
		}

		if(!ssl_data->key_passphrase().empty())
		{
			check_error(curl_easy_setopt(curl, CURLOPT_KEYPASSWD, ssl_data->key_passphrase().c_str()));
		}

		if(!ssl_data->key().empty())
		{
			check_error(curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, ssl_data->cert_type().c_str()));
			check_error(curl_easy_setopt(curl, CURLOPT_SSLKEY, ssl_data->key().c_str()));
		}

		if(!ssl_data->ca_cert().empty())
		{
			check_error(curl_easy_setopt(curl, CURLOPT_CAINFO, ssl_data->ca_cert().c_str()));
		}

		if(ssl_data->verify_peer())
		{
			check_error(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L));
			check_error(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L));
		}
		else
		{
			check_error(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0));
			check_error(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0));
		}

		if(ssl_data->bt_auth_header())
		{
			check_error(curl_easy_setopt(curl, CURLOPT_HTTPHEADER, ssl_data->bt_auth_header()));
		}
	}
}

string sinsp_curl::get_data()
{
	std::ostringstream os;
	if(get_data(os))
	{
		return os.str();
	}
	g_logger.log("CURL error: [" + os.str() + ']', sinsp_logger::SEV_ERROR);
	return "";
}

bool sinsp_curl::get_data(std::ostream& os)
{
	CURLcode res = CURLE_OK;
	check_error(curl_easy_setopt(m_curl, CURLOPT_URL, m_uri.to_string().c_str()));
	check_error(curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1L));
	check_error(curl_easy_setopt(m_curl, CURLOPT_CONNECTTIMEOUT, static_cast<int>(m_timeout_ms / 1000)));
	check_error(curl_easy_setopt(m_curl, CURLOPT_TIMEOUT_MS, m_timeout_ms));
	check_error(curl_easy_setopt(m_curl, CURLOPT_NOSIGNAL, 1)); //Prevent "longjmp causes uninitialized stack frame" bug
	check_error(curl_easy_setopt(m_curl, CURLOPT_ACCEPT_ENCODING, "deflate"));
	check_error(curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, &sinsp_curl::write_data));
	check_error(curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &os));

	res = curl_easy_perform(m_curl);
	if(res != CURLE_OK)
	{
		os << curl_easy_strerror(res) << std::flush;
	}
	else
	{
		// HTTP errors are not returned by curl API
		// error will be in the response stream
		long http_code = 0;
		check_error(curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &http_code));
		if(http_code >= 400)
		{
			g_logger.log("CURL HTTP error: " + std::to_string(http_code), sinsp_logger::SEV_ERROR);
			return false;
		}
	}

	return res == CURLE_OK;
}

size_t sinsp_curl::write_data(void *ptr, size_t size, size_t nmemb, void *cb)
{
	std::string data(reinterpret_cast<const char*>(ptr), static_cast<size_t>(size * nmemb));
	*reinterpret_cast<std::ostream*>(cb) << data << std::flush;
	return size * nmemb;
}

void sinsp_curl::check_error(unsigned ret)
{
	if(ret >= CURL_LAST)
	{
		throw sinsp_exception("Invalid CURL return value:" + std::to_string(ret));
	}

	CURLcode res = (CURLcode)ret;
	if(CURLE_OK != res && CURLE_AGAIN != res)
	{
		std::ostringstream os;
		os << "Error: " << curl_easy_strerror(res);
		throw sinsp_exception(os.str());
	}
}

void sinsp_curl::dump(const char *text, FILE *stream, unsigned char *ptr, size_t size, char nohex)
{
	size_t i;
	size_t c;
	unsigned int width=0x10;
	if(nohex)
	{
		width = 0x40;
	}
	fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n", text, (long)size, (long)size);

	for(i=0; i<size; i+= width)
	{
		fprintf(stream, "%4.4lx: ", (long)i);
		if(!nohex)
		{
		  for(c = 0; c < width; c++)
		  {
			if(i+c < size)
			{
				fprintf(stream, "%02x ", ptr[i+c]);
			}
			else
			{
				fputs("   ", stream);
			}
		  }
		}

	for(c = 0; (c < width) && (i+c < size); c++)
	{
		if(nohex && (i+c+1 < size) && ptr[i+c]==0x0D && ptr[i+c+1]==0x0A)
		{
			i+=(c+2-width);
			break;
		}
		fprintf(stream, "%c", (ptr[i+c]>=0x20) && (ptr[i+c]<0x80)?ptr[i+c]:'.');
		if(nohex && (i+c+2 < size) && ptr[i+c+1]==0x0D && ptr[i+c+2]==0x0A)
		{
			i+=(c+3-width);
			break;
		}
	}
	fputc('\n', stream);
  }
  fflush(stream);
}

int sinsp_curl::trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
	struct data *config = (struct data *)userp;
	const char *text;
	(void)handle; // prevent compiler warning
	switch (type)
	{
		case CURLINFO_TEXT:
			fprintf(stderr, "== Info: %s", data);
		default: // in case a new one is introduced to shock us
			return 0;
		case CURLINFO_HEADER_OUT:
			text = "=> Send header";
			break;
		case CURLINFO_DATA_OUT:
			text = "=> Send data";
			break;
		case CURLINFO_SSL_DATA_OUT:
			text = "=> Send SSL data";
			break;
		case CURLINFO_HEADER_IN:
			text = "<= Recv header";
			break;
		case CURLINFO_DATA_IN:
			text = "<= Recv data";
			break;
		case CURLINFO_SSL_DATA_IN:
			text = "<= Recv SSL data";
			break;
	}
	dump(text, stderr, (unsigned char *)data, size, config->trace_ascii);
	return 0;
}

//
// sinsp_curl::ssl
//

sinsp_curl::ssl::ssl(const std::string& cert, const std::string& key, const std::string& key_passphrase,
	const std::string& ca_cert, bool verify_peer, const std::string& cert_type,
	const std::string& bearer_token):
		m_cert_type(cert_type), m_cert(cert), m_key(key), m_key_passphrase(key_passphrase),
		m_ca_cert(ca_cert), m_verify_peer(verify_peer),
		m_bearer_token(stringize_file(bearer_token)), m_bt_auth_header(0)
{
	std::size_t len = m_bearer_token.length(); // curl does not tolerate newlines in headers
	while(len && (m_bearer_token[len-1] == '\r' || m_bearer_token[len-1] == '\n'))
	{
		m_bearer_token.erase(len-1);
		len = m_bearer_token.length();
	}
	if(len)
	{
		std::string hdr = "Authorization: Bearer ";
		hdr.append(m_bearer_token);
		m_bt_auth_header = curl_slist_append(m_bt_auth_header, hdr.c_str());
	}
}

sinsp_curl::ssl::~ssl()
{
	if(m_bt_auth_header)
	{
		curl_slist_free_all(m_bt_auth_header);
	}
}

std::string sinsp_curl::ssl::stringize_file(const std::string& disk_file)
{
	std::string tmp, content;
	std::ifstream ifs(disk_file);
	while(std::getline(ifs, tmp))
	{
		content.append(tmp).append(1, '\n');
	}
	return content;
}

std::string sinsp_curl::ssl::memorize_file(const std::string& disk_file)
{
	std::string mem_file;
	if(disk_file.empty())
	{
		return mem_file;
	}
	std::string::size_type pos = disk_file.rfind('/');
	if(pos == std::string::npos)
	{
		mem_file.append(1, '/').append(disk_file);
	}
	else
	{
		mem_file.append(disk_file.substr(pos, disk_file.size() - pos));
	}
	mem_file.append(1, '~');
	int fd = shm_open(mem_file.c_str(), O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
	if(fd != -1)
	{
		char buf[FILENAME_MAX] = { 0 };
		std::ifstream ifs(disk_file);
		std::string fd_path = "/proc/self/fd/" + std::to_string(fd);
		ssize_t sz = readlink(fd_path.c_str(), buf, sizeof(buf));
		if(sz != -1 && sz <= static_cast<ssize_t>(sizeof(buf)))
		{
			mem_file.assign(buf, sz);
			std::string str;
			std::ofstream ofs(mem_file, std::ofstream::out);
			while(std::getline(ifs, str))
			{
				ofs << str << '\n';
			}
		}
		else
		{
			std::ostringstream os;
			os << "Error occurred while trying to determine the real path of memory file [" << fd_path << "]: "
				<< strerror(errno) << " (disk file [" << disk_file << "] will be used).";
			g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
			return disk_file;
		}
	}
	else
	{
		std::ostringstream os;
		os << "Memory file creation error: " << strerror(errno) << " (disk file [" << disk_file << "] will be used).";
		g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
		return disk_file;
	}
	return mem_file;
}

void sinsp_curl::ssl::unmemorize_file(const std::string& mem_file)
{
	if(shm_unlink(mem_file.c_str()) == 0)
	{
		std::ostringstream os;
		os << "Memory file [" << mem_file << "] unlink error: " << strerror(errno);
		g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
	}
}

#endif // __linux__

