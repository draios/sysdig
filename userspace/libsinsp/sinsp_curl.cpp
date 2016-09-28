//
// sinsp_curl.cpp
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
#include <cstring>

sinsp_curl::data sinsp_curl::m_config;

sinsp_curl::sinsp_curl(const uri& url, long timeout_ms, bool debug):
	m_curl(curl_easy_init()), m_uri(url), m_timeout_ms(timeout_ms), m_debug(debug)

{
	init();
}

sinsp_curl::sinsp_curl(const uri& url, const std::string& bearer_token_file, long timeout_ms, bool debug):
	m_curl(curl_easy_init()), m_uri(url), m_timeout_ms(timeout_ms), m_bt(new bearer_token(bearer_token_file)),
	m_debug(debug)
{
	init();
}

sinsp_curl::sinsp_curl(const uri& url,
	const std::string& cert, const std::string& key, const std::string& key_passphrase,
	const std::string& ca_cert, bool verify_peer, const std::string& cert_type,
	const std::string& bearer_token_file,
	long timeout_ms, bool debug):
		m_curl(curl_easy_init()), m_uri(url), m_timeout_ms(timeout_ms),
		m_ssl(new ssl(cert, key, key_passphrase, ca_cert, verify_peer, cert_type)),
		m_bt(new bearer_token(bearer_token_file)),
		m_debug(debug)
{
	init();
}

sinsp_curl::sinsp_curl(const uri& url, ssl::ptr_t p_ssl, bearer_token::ptr_t p_bt, long timeout_ms, bool debug):
		m_curl(curl_easy_init()), m_uri(url), m_timeout_ms(timeout_ms),
		m_ssl(p_ssl),
		m_bt(p_bt),
		m_debug(debug)
{
	init();
}

void sinsp_curl::init()
{
	if(!m_curl)
	{
		throw sinsp_exception("Cannot initialize CURL.");
	}

	check_error(curl_easy_setopt(m_curl, CURLOPT_FORBID_REUSE, 1L));

	if(m_ssl)
	{
		init_ssl(m_curl, m_ssl);
	}

	if(m_bt)
	{
		init_bt(m_curl, m_bt);
	}

	enable_debug(m_curl, m_debug);
}

sinsp_curl::~sinsp_curl()
{
	curl_easy_cleanup(m_curl);
}

void sinsp_curl::init_bt(CURL* curl, bearer_token::ptr_t bt)
{
	if(bt && bt->bt_auth_header())
	{
		check_error(curl_easy_setopt(curl, CURLOPT_HTTPHEADER, bt->bt_auth_header()));
	}
}

void sinsp_curl::enable_debug(CURL* curl, bool enable)
{
	if(curl)
	{
		curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, &sinsp_curl::trace);
		curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &m_config);
		long en = 0L;
		if(enable) { en = 1L; }
		m_config.trace_ascii = en;
		curl_easy_setopt(curl, CURLOPT_VERBOSE, en);
	}
}

void sinsp_curl::init_ssl(CURL* curl, ssl::ptr_t ssl_data)
{
	if(curl && ssl_data)
	{
		if(!ssl_data->cert().empty())
		{
			if(!ssl_data->cert_type().empty())
			{
				check_error(curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, ssl_data->cert_type().c_str()));
			}
			check_error(curl_easy_setopt(curl, CURLOPT_SSLCERT, ssl_data->cert().c_str()));
			g_logger.log("CURL SSL certificate: " + ssl_data->cert(), sinsp_logger::SEV_DEBUG);
		}

		if(!ssl_data->key_passphrase().empty())
		{
			check_error(curl_easy_setopt(curl, CURLOPT_KEYPASSWD, ssl_data->key_passphrase().c_str()));
			g_logger.log("CURL SSL key password SET. ", sinsp_logger::SEV_DEBUG);
		}

		if(!ssl_data->key().empty())
		{
			if(!ssl_data->cert_type().empty())
			{
				check_error(curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, ssl_data->cert_type().c_str()));
			}
			check_error(curl_easy_setopt(curl, CURLOPT_SSLKEY, ssl_data->key().c_str()));
			g_logger.log("CURL SSL key: " + ssl_data->key(), sinsp_logger::SEV_DEBUG);
		}

		if(ssl_data->verify_peer())
		{
			check_error(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L));
			check_error(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L));
			g_logger.log("CURL SSL peer and host verification ENABLED.", sinsp_logger::SEV_DEBUG);
		}
		else
		{
			check_error(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0));
			check_error(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0));
			g_logger.log("CURL SSL peer and host verification DISABLED.", sinsp_logger::SEV_DEBUG);
		}

		if(!ssl_data->ca_cert().empty())
		{
			check_error(curl_easy_setopt(curl, CURLOPT_CAINFO, ssl_data->ca_cert().c_str()));
			g_logger.log("CURL SSL CA cert set to: " + ssl_data->ca_cert(), sinsp_logger::SEV_DEBUG);
		}
	}
}

string sinsp_curl::get_data(bool do_log)
{
	std::ostringstream os;
	if(get_data(os))
	{
		return os.str();
	}
	if(do_log)
	{
		g_logger.log("CURL error while connecting to " + m_uri.to_string(false) + ", "
					 "response: [" + os.str() + ']', sinsp_logger::SEV_ERROR);
	}
	return "";
}

size_t sinsp_curl::header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
	size_t sz = nitems * size;
	std::string buf(buffer, sz);
	const std::string loc = "Location:";
	const std::string nl = "\r\n";
	std::string::size_type loc_pos = buf.find(loc);
	std::string::size_type nl_pos = buf.find(nl);
	if((loc_pos != std::string::npos) && (nl_pos != std::string::npos) &&
	   (nl_pos - loc.length() > (loc + nl).length()))
	{
		std::string::size_type url_pos = buf.find("http://", loc_pos);
		if(url_pos == std::string::npos)
		{
			url_pos = buf.find("//", loc_pos);
			if(url_pos != std::string::npos) // still absolute
			{
				buf = buf.substr(url_pos, nl_pos-url_pos);
				buf.insert(0, "http:");
			}
			else // relative
			{
				buf = buf.substr(loc.length(), nl_pos-loc.length());
			}
		}
		else
		{
			buf = buf.substr(url_pos, nl_pos-url_pos);
		}
		trim(buf);
		sz = buf.length();
		if(sz < CURL_MAX_HTTP_HEADER)
		{
			g_logger.log("HTTP redirect Location: (" + buf + ')', sinsp_logger::SEV_TRACE);
			std::strncpy((char*)userdata, buf.data(), sz);
			((char*)userdata)[sz] = 0;
		}
	}
	return nitems * size;
}

bool sinsp_curl::is_redirect(long http_code)
{
	return ((http_code >= 301 && http_code <= 303) ||
			(http_code >= 307 && http_code <= 308));
}

bool sinsp_curl::handle_redirect(uri& url, std::string&& loc, std::ostream& os)
{
	if(!loc.empty())
	{
		g_logger.log("HTTP redirect  received from [" + url.to_string(false) + ']',
					 sinsp_logger::SEV_INFO);
		std::string::size_type url_pos = loc.find("//");
		if(url_pos != std::string::npos)
		{
			uri::credentials_t creds;
			url.get_credentials(creds);
			url = trim(loc);
			if(!creds.first.empty())
			{
				url.set_credentials(creds);
			}
		}
		else // location relative, take just path
		{
			url.set_path(trim(loc));
		}
		g_logger.log("HTTP redirecting to [" + url.to_string(false) + "].",
					 sinsp_logger::SEV_INFO);
		return true;
	}
	else
	{
		g_logger.log("CURL redirect received from [" + url.to_string(false) + "], "
					 "but location not found.", sinsp_logger::SEV_ERROR);
		return false;
	}
	return false;
}

bool sinsp_curl::get_data(std::ostream& os)
{
	CURLcode res = CURLE_OK;
	check_error(curl_easy_setopt(m_curl, CURLOPT_URL, m_uri.to_string().c_str()));
	check_error(curl_easy_setopt(m_curl, CURLOPT_HEADERDATA, m_redirect));
	check_error(curl_easy_setopt(m_curl, CURLOPT_HEADERFUNCTION, header_callback));
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
		else if(is_redirect(http_code))
		{
			g_logger.log("HTTP redirect (" + std::to_string(http_code) + ')', sinsp_logger::SEV_DEBUG);
			if(handle_redirect(m_uri, std::string(m_redirect), os))
			{
				std::ostringstream* pos = dynamic_cast<std::ostringstream*>(&os);
				if(pos)
				{
					pos->str("");
					return get_data(*pos);
				}
				else
				{
					g_logger.log("HTTP redirect received from [" + m_uri.to_string(false) + "] but "
							 "output stream can not be obtained (dynamic cast failed).",
							 sinsp_logger::SEV_ERROR);
					return false;
				}
			}
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

bool sinsp_curl::check_error(unsigned ret, bool exc)
{
	if(ret >= CURL_LAST && exc)
	{
		throw sinsp_exception("Invalid CURL return value:" + std::to_string(ret));
	}
	else { return false; }

	CURLcode res = (CURLcode)ret;
	if(CURLE_OK != res && CURLE_AGAIN != res && exc)
	{
		std::ostringstream os;
		os << "Error: " << curl_easy_strerror(res);
		throw sinsp_exception(os.str());
	}
	else { return false; }
	return true;
}

void sinsp_curl::dump(const char *text, unsigned char *ptr, size_t size, char nohex)
{
	const std::size_t DBG_BUF_SIZE = 1024;
	char stream[DBG_BUF_SIZE] = { 0 };
	std::ostringstream os;
	size_t i;
	size_t c;
	unsigned int width = 0x10;
	if(nohex)
	{
		width = 0x40;
	}
	snprintf(stream, DBG_BUF_SIZE, "%s, %10.10ld bytes (0x%8.8lx)\n", text, (long)size, (long)size);
	os << stream;
	for(i=0; i<size; i+= width)
	{
		snprintf(stream, DBG_BUF_SIZE, "%4.4lx: ", (long)i);
		os << stream;
		if(!nohex)
		{
		  for(c = 0; c < width; c++)
		  {
			if(i+c < size)
			{
				snprintf(stream, DBG_BUF_SIZE, "%02x ", ptr[i+c]);
			}
			else
			{
				snprintf(stream, DBG_BUF_SIZE, "%s", "   ");
			}
			os << stream;
		  }
		}

		for(c = 0; (c < width) && (i+c < size); c++)
		{
			if(nohex && (i+c+1 < size) && ptr[i+c]==0x0D && ptr[i+c+1]==0x0A)
			{
				i+=(c+2-width);
				break;
			}
			snprintf(stream, DBG_BUF_SIZE, "%c", (ptr[i+c]>=0x20) && (ptr[i+c]<0x80)?ptr[i+c]:'.');
			os << stream;
			if(nohex && (i+c+2 < size) && ptr[i+c+1]==0x0D && ptr[i+c+2]==0x0A)
			{
				i+=(c+3-width);
				break;
			}
		}
		snprintf(stream, DBG_BUF_SIZE, "%c", '\n');
		os << stream;
	}
	g_logger.log("CURL: " + os .str(), sinsp_logger::SEV_DEBUG);
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
	dump(text, (unsigned char *)data, size, config->trace_ascii);
	return 0;
}

#endif // __linux__

