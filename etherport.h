/* OpenSprinkler Unified (AVR/RPI/BBB/LINUX) Firmware
 * Copyright (C) 2015 by Ray Wang (ray@opensprinkler.com)
 *
 * Linux Ethernet functions header file
 * This file is based on Richard Zimmerman's sprinklers_pi program
 * Copyright (c) 2013 Richard Zimmerman
 *
 * This file is part of the OpenSprinkler library
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _ETHERPORT_H_
#define _ETHERPORT_H_

#if defined(ARDUINO)

#else // headers for RPI/BBB

#include <stdio.h>
#include <inttypes.h>
#include <ctype.h>

#ifdef __APPLE__
#define MSG_NOSIGNAL SO_NOSIGPIPE
#endif

class EthernetServer;

class EthernetClient {
public:
	EthernetClient();
	EthernetClient(int sock);
	~EthernetClient();
	int connect(uint8_t ip[4], uint16_t port);
	bool connected();
	void stop();
	int read(uint8_t *buf, size_t size);
	size_t write(const uint8_t *buf, size_t size);
	operator bool();
	int GetSocket()
	{
		return m_sock;
	}
private:
	int m_sock;
	bool m_connected;
	friend class EthernetServer;
};

class EthernetServer {
public:
	EthernetServer(uint16_t port);
	~EthernetServer();

	bool begin();
	EthernetClient available();
private:
	uint16_t m_port;
	int m_sock;
};
#ifdef B_64
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define String       string
#define FPSTR(pstr_pointer) (reinterpret_cast<const __FlashStringHelper *>(pstr_pointer))
#ifdef DEBUG_ESP_HTTP_SERVER
#ifdef DEBUG_ESP_PORT
#define DBGWS(f,...) do { DEBUG_ESP_PORT.printf(PSTR(f), ##__VA_ARGS__); } while (0)
#else
#define DBGWS(f,...) do { Serial.printf(PSTR(f), ##__VA_ARGS__); } while (0)
#endif
#else
#define DBGWS(x...) do { (void)0; } while (0)
#endif

enum HTTPMethod { HTTP_ANY, HTTP_GET, HTTP_HEAD, HTTP_POST, HTTP_PUT, HTTP_PATCH, HTTP_DELETE, HTTP_OPTIONS };
enum HTTPUploadStatus { UPLOAD_FILE_START, UPLOAD_FILE_WRITE, UPLOAD_FILE_END,
                        UPLOAD_FILE_ABORTED };
enum HTTPClientStatus { HC_NONE, HC_WAIT_READ, HC_WAIT_CLOSE };
enum HTTPAuthMethod { BASIC_AUTH, DIGEST_AUTH };

#define WEBSERVER_HAS_HOOK 1

#define HTTP_DOWNLOAD_UNIT_SIZE 1460

#ifndef HTTP_UPLOAD_BUFLEN
#define HTTP_UPLOAD_BUFLEN 2048
#endif

#define HTTP_MAX_DATA_WAIT 5000 //ms to wait for the client to send the request
#define HTTP_MAX_POST_WAIT 5000 //ms to wait for POST data to arrive
#define HTTP_MAX_SEND_WAIT 5000 //ms to wait for data chunk to be ACKed
#define HTTP_MAX_CLOSE_WAIT 2000 //ms to wait for the client to close the connection

#define CONTENT_LENGTH_UNKNOWN ((size_t) -1)
#define CONTENT_LENGTH_NOT_SET ((size_t) -2)

typedef struct {
  HTTPUploadStatus status;
  String  filename;
  String  name;
  String  type;
  size_t  totalSize;    // total size of uploaded file so far
  size_t  currentSize;  // size of data currently in buf
  size_t  contentLength; // size of entire post request, file size + headers and other request data.
  uint8_t buf[HTTP_UPLOAD_BUFLEN];
} HTTPUpload;

namespace esp8266webserver {

// an abstract class used as a means to proide a unique pointer type
// but really has no body
//class __FlashStringHelper;
//#define FPSTR(pstr_pointer) (reinterpret_cast<const __FlashStringHelper *>(pstr_pointer))
//#define F(string_literal) (FPSTR(PSTR(string_literal)))

// support libraries that expect this name to be available
// replace with `using StringSumHelper = String;` in case something wants this constructible
//class StringSumHelper;
//extern const String emptyString;

template<typename ServerType>
class ESP8266WebServerTemplate;

template<typename ServerType>
class FunctionRequestHandler : public RequestHandler<ServerType> {
    using WebServerType = ESP8266WebServerTemplate<ServerType>;
public:
    FunctionRequestHandler(typename WebServerType::THandlerFunction fn, typename WebServerType::THandlerFunction ufn, const Uri &uri, HTTPMethod method)
    : _fn(fn)
    , _ufn(ufn)
    , _uri(uri.clone())
    , _method(method)
    {
    }

    ~FunctionRequestHandler() {
        delete _uri;
    }

    bool canHandle(HTTPMethod requestMethod, const String& requestUri) override  {
        if (_method != HTTP_ANY && _method != requestMethod)
            return false;

        return _uri->canHandle(requestUri, RequestHandler<ServerType>::pathArgs);
    }

    bool canUpload(const String& requestUri) override  {
        if (!_ufn || !canHandle(HTTP_POST, requestUri))
            return false;

        return true;
    }

    bool handle(WebServerType& server, HTTPMethod requestMethod, const String& requestUri) override {
        (void) server;
        if (!canHandle(requestMethod, requestUri))
            return false;

        _fn();
        return true;
    }

    void upload(WebServerType& server, const String& requestUri, HTTPUpload& upload) override {
        (void) server;
        (void) upload;
        if (canUpload(requestUri))
            _ufn();
    }

protected:
    typename WebServerType::THandlerFunction _fn;
    typename WebServerType::THandlerFunction _ufn;
    Uri *_uri;
    HTTPMethod _method;
};

template<typename ServerType>
class StaticRequestHandler : public RequestHandler<ServerType> {
    using WebServerType = ESP8266WebServerTemplate<ServerType>;
public:
    StaticRequestHandler(FS& fs, const char* path, const char* uri, const char* cache_header)
    : _fs(fs)
    , _uri(uri)
    , _path(path)
    , _cache_header(cache_header)
    {
        DEBUGV("StaticRequestHandler: path=%s uri=%s, cache_header=%s\r\n", path, uri, cache_header == __null ? "" : cache_header);
    }

    bool validMethod(HTTPMethod requestMethod){
        return (requestMethod == HTTP_GET) || (requestMethod == HTTP_HEAD);
    }

    /* Deprecated version. Please use mime::getContentType instead */
    static String getContentType(const String& path) __attribute__((deprecated)) {
        return mime::getContentType(path);
    }

protected:
    FS _fs;
    String _uri;
    String _path;
    String _cache_header;
};

#if 0
template<typename ServerType>
class StaticDirectoryRequestHandler : public StaticRequestHandler<ServerType> {

    using SRH = StaticRequestHandler<ServerType>;
    using WebServerType = ESP8266WebServerTemplate<ServerType>;

public:
    StaticDirectoryRequestHandler(FS& fs, const char* path, const char* uri, const char* cache_header)
        :
    SRH(fs, path, uri, cache_header),
    _baseUriLength{SRH::_uri.length()}
    {}

    bool canHandle(HTTPMethod requestMethod, const String& requestUri) override {
        return SRH::validMethod(requestMethod) && requestUri.startsWith(SRH::_uri);
    }

    bool handle(WebServerType& server, HTTPMethod requestMethod, const String& requestUri) override {

        if (!canHandle(requestMethod, requestUri))
            return false;

        DEBUGV("DirectoryRequestHandler::handle: request=%s _uri=%s\r\n", requestUri.c_str(), SRH::_uri.c_str());

        String path;
        path.reserve(SRH::_path.length() + requestUri.length() + 32);
        path = SRH::_path;

        // Append whatever follows this URI in request to get the file path.
        path += requestUri.substr(_baseUriLength);

        // Base URI doesn't point to a file.
        // If a directory is requested, look for index file.
        if (path.endsWith("/"))
            path += F("index.htm");

        // If neither <blah> nor <blah>.gz exist, and <blah> is a file.htm, try it with file.html instead
        // For the normal case this will give a search order of index.htm, index.htm.gz, index.html, index.html.gz
        if (!SRH::_fs.exists(path) && !SRH::_fs.exists(path + ".gz") && path.endsWith(".htm")) {
            path += 'l';
        }

        DEBUGV("DirectoryRequestHandler::handle: path=%s\r\n", path.c_str());

        String contentType = mime::getContentType(path);

        using namespace mime;
        // look for gz file, only if the original specified path is not a gz.  So part only works to send gzip via content encoding when a non compressed is asked for
        // if you point the the path to gzip you will serve the gzip as content type "application/x-gzip", not text or javascript etc...
        if (!path.endsWith(FPSTR(mimeTable[gz].endsWith)) && !SRH::_fs.exists(path))  {
            String pathWithGz = path + FPSTR(mimeTable[gz].endsWith);
            if(SRH::_fs.exists(pathWithGz))
                path += FPSTR(mimeTable[gz].endsWith);
        }

        File f = SRH::_fs.open(path, "r");
        if (!f)
            return false;

        if (!f.isFile()) {
            f.close();
            return false;
        }

        if (SRH::_cache_header.length() != 0)
            server.sendHeader("Cache-Control", SRH::_cache_header);

        server.streamFile(f, contentType, requestMethod);
        return true;
    }

protected:
    size_t _baseUriLength;
};

template<typename ServerType>
class StaticFileRequestHandler
    :
public StaticRequestHandler<ServerType> {

    using SRH = StaticRequestHandler<ServerType>;
    using WebServerType = ESP8266WebServerTemplate<ServerType>;

public:
    StaticFileRequestHandler(FS& fs, const char* path, const char* uri, const char* cache_header)
        :
    StaticRequestHandler<ServerType>{fs, path, uri, cache_header}
    {
        File f = SRH::_fs.open(path, "r");
        MD5Builder calcMD5;
        calcMD5.begin();
        calcMD5.addStream(f, f.size());
        calcMD5.calculate();
        calcMD5.getBytes(_ETag_md5);
        f.close();
    }

    bool canHandle(HTTPMethod requestMethod, const String& requestUri) override  {
        return SRH::validMethod(requestMethod) && requestUri == SRH::_uri;
    }

    bool handle(WebServerType& server, HTTPMethod requestMethod, const String & requestUri) override {
        if (!canHandle(requestMethod, requestUri))
            return false;

        const String etag = "\"" + base64::encode(_ETag_md5, 16, false) + "\"";

        if(server.header("If-None-Match") == etag){
            server.send(304);
            return true;
        }

        File f = SRH::_fs.open(SRH::_path, "r");

        if (!f)
            return false;

        if (!f.isFile()) {
            f.close();
            return false;
        }

        if (SRH::_cache_header.length() != 0)
            server.sendHeader("Cache-Control", SRH::_cache_header);

        server.sendHeader("ETag", etag);

        server.streamFile(f, mime::getContentType(SRH::_path), requestMethod);
        return true;
    }

protected:
    uint8_t _ETag_md5[16];       
};
#endif

using ParseArgumentsHookFunction = std::function<void(String&,String&,const String&,int,int,int,int)>;

template<typename ServerType>
class ESP8266WebServerTemplate
{
public:
  ESP8266WebServerTemplate(IPAddress addr, int port = 80);
  ESP8266WebServerTemplate(int port = 80);
  ~ESP8266WebServerTemplate();
  typedef std::function<void(void)> THandlerFunction;

  using ClientType = typename ServerType::ClientType;
  using RequestHandlerType = RequestHandler<ServerType>;
  using WebServerType = ESP8266WebServerTemplate<ServerType>;
  enum ClientFuture { CLIENT_REQUEST_CAN_CONTINUE, CLIENT_REQUEST_IS_HANDLED, CLIENT_MUST_STOP, CLIENT_IS_GIVEN };
  typedef String (*ContentTypeFunction) (const String&);
  using HookFunction = std::function<ClientFuture(const String& method, const String& url, WiFiClient* client, ContentTypeFunction contentType)>;

  void begin();
  void begin(uint16_t port);
  void handleClient();
  void close();
  void stop();

  bool authenticate(const char * username, const char * password);
  bool authenticateDigest(const String& username, const String& H1);
  void requestAuthentication(HTTPAuthMethod mode = BASIC_AUTH, const char* realm = NULL, const String& authFailMsg = String("") );

  void on(const Uri &uri, THandlerFunction handler);
  void on(const Uri &uri, HTTPMethod method, THandlerFunction fn);
  void on(const Uri &uri, HTTPMethod method, THandlerFunction fn, THandlerFunction ufn);
  void addHandler(RequestHandlerType* handler);
  void serveStatic(const char* uri, fs::FS& fs, const char* path, const char* cache_header = NULL );
  void onNotFound(THandlerFunction fn);  //called when handler is not assigned
  void onFileUpload(THandlerFunction fn); //handle file uploads
  void enableCORS(bool enable);

  const String& uri() const { return _currentUri; }
  HTTPMethod method() const { return _currentMethod; }
  ClientType& client() { return _currentClient; }
  HTTPUpload& upload() { return *_currentUpload; }

  // Allows setting server options (i.e. SSL keys) by the instantiator
  ServerType &getServer() { return _server; }

  const String& pathArg(unsigned int i) const; // get request path argument by number
  const String& arg(const String& name) const;    // get request argument value by name
  const String& arg(int i) const;          // get request argument value by number
  const String& argName(int i) const;      // get request argument name by number
  int args() const;                        // get arguments count
  bool hasArg(const String& name) const;   // check if argument exists
  void collectHeaders(const char* headerKeys[], const size_t headerKeysCount); // set the request headers to collect
  template<typename... Args>
  void collectHeaders(const Args&... args); // set the request headers to collect (variadic template version)
  const String& header(const String& name) const; // get request header value by name
  const String& header(int i) const;       // get request header value by number
  const String& headerName(int i) const;   // get request header name by number
  int headers() const;                     // get header count
  bool hasHeader(const String& name) const;       // check if header exists
  const String& hostHeader() const;        // get request host header if available or empty String if not

  // send response to the client
  // code - HTTP response code, can be 200 or 404
  // content_type - HTTP content type, like "text/plain" or "image/png"
  // content - actual content body
  void send(int code, const char* content_type = NULL, const String& content = emptyString);
  void send(int code, char* content_type, const String& content);
  void send(int code, const String& content_type, const String& content);
  void send(int code, const char *content_type, const char *content) {
    send_P(code, content_type, content);
  }
  void send(int code, const char *content_type, const char *content, size_t content_length) {
    send_P(code, content_type, content, content_length);
  }
  void send(int code, const char *content_type, const uint8_t *content, size_t content_length) {
    send_P(code, content_type, (const char *)content, content_length);
  }
  void send_P(int code, PGM_P content_type, PGM_P content);
  void send_P(int code, PGM_P content_type, PGM_P content, size_t contentLength);

  void send(int code, const char* content_type, Stream* stream, size_t content_length = 0);
  void send(int code, const char* content_type, Stream& stream, size_t content_length = 0);

  void setContentLength(const size_t contentLength);
  void sendHeader(const String& name, const String& value, bool first = false);
  void sendContent(const String& content);
  void sendContent(String& content) {
    sendContent((const String&)content);
  }
  void sendContent_P(PGM_P content);
  void sendContent_P(PGM_P content, size_t size);
  void sendContent(const char *content) { sendContent_P(content); }
  void sendContent(const char *content, size_t size) { sendContent_P(content, size); }

  void sendContent(Stream* content, ssize_t content_length = 0);
  void sendContent(Stream& content, ssize_t content_length = 0) { sendContent(&content, content_length); }

  bool chunkedResponseModeStart_P (int code, PGM_P content_type) {
    if (_currentVersion == 0)
        // no chunk mode in HTTP/1.0
        return false;
    setContentLength(CONTENT_LENGTH_UNKNOWN);
    send_P(code, content_type, "");
    return true;
  }
  bool chunkedResponseModeStart (int code, const char* content_type) {
    return chunkedResponseModeStart_P(code, content_type);
  }
  bool chunkedResponseModeStart (int code, const String& content_type) {
    return chunkedResponseModeStart_P(code, content_type.c_str());
  }
  void chunkedResponseFinalize () {
    sendContent(emptyString);
  }

  // Whether other requests should be accepted from the client on the
  // same socket after a response is sent.
  // This will automatically configure the "Connection" header of the response.
  // Defaults to true when the client's HTTP version is 1.1 or above, otherwise it defaults to false.
  // If the client sends the "Connection" header, the value given by the header is used.
  void keepAlive(bool keepAlive) { _keepAlive = keepAlive; }
  bool keepAlive() { return _keepAlive; }

  static String credentialHash(const String& username, const String& realm, const String& password);

  static String urlDecode(const String& text);

  // Handle a GET request by sending a response header and stream file content to response body
  template<typename T>
  size_t streamFile(T &file, const String& contentType) {
    return streamFile(file, contentType, HTTP_GET);
  }

  // Implement GET and HEAD requests for files.
  // Stream body on HTTP_GET but not on HTTP_HEAD requests.
  template<typename T>
  size_t streamFile(T &file, const String& contentType, HTTPMethod requestMethod) {
    size_t contentLength = 0;
    _streamFileCore(file.size(), file.name(), contentType);
    if (requestMethod == HTTP_GET) {
      contentLength = file.sendAll(_currentClient);
    }
    return contentLength;
  }

  // Implement GET and HEAD requests for stream
  // Stream body on HTTP_GET but not on HTTP_HEAD requests.
  template<typename T>
  size_t stream(T &aStream, const String& contentType, HTTPMethod requestMethod, ssize_t size) {
    setContentLength(size);
    send(200, contentType, emptyString);
    if (requestMethod == HTTP_GET)
        size = aStream.sendSize(_currentClient, size);
    return size;
  }

  // Implement GET and HEAD requests for stream
  // Stream body on HTTP_GET but not on HTTP_HEAD requests.
  template<typename T>
  size_t stream(T& aStream, const String& contentType, HTTPMethod requestMethod = HTTP_GET) {
    ssize_t size = aStream.size();
    if (size < 0)
    {
        send(500, F("text/html"), F("input stream: undetermined size"));
        return 0;
    }
    return stream(aStream, contentType, requestMethod, size);
  }

  static String responseCodeToString(const int code);

  void addHook (HookFunction hook) {
    if (_hook) {
      auto previousHook = _hook;
      _hook = [previousHook, hook](const String& method, const String& url, WiFiClient* client, ContentTypeFunction contentType) {
          auto whatNow = previousHook(method, url, client, contentType);
          if (whatNow == CLIENT_REQUEST_CAN_CONTINUE)
            return hook(method, url, client, contentType);
          return whatNow;
        };
    } else {
      _hook = hook;
    }
  }

protected:
  void _addRequestHandler(RequestHandlerType* handler);
  void _handleRequest();
  void _finalizeResponse();
  ClientFuture _parseRequest(ClientType& client);
  void _parseArguments(const String& data);
  
  int _parseArgumentsPrivate(const String& data, ParseArgumentsHookFunction handler){
    DBGWS("args: %s\n", data.c_str());

    size_t pos = 0;
    int arg_total = 0;

    while (true) {

      // skip empty expression
      while (data[pos] == '&' || data[pos] == ';')
        if (++pos >= data.length())
          break;

      // locate separators
      int equal_index = data.find('=', pos);
      int key_end_pos = equal_index;
      int next_index = data.find('&', pos);
      int next_index2 = data.find(';', pos);
      if ((next_index == -1) || (next_index2 != -1 && next_index2 < next_index))
        next_index = next_index2;
      if ((key_end_pos == -1) || ((key_end_pos > next_index) && (next_index != -1)))
        key_end_pos = next_index;
      if (key_end_pos == -1)
        key_end_pos = data.length();

      // handle key/value
      if ((int)pos < key_end_pos) {

        RequestArgument& arg = _currentArgs[arg_total];
        handler(arg.key, arg.value, data, equal_index, pos, key_end_pos, next_index);

        ++arg_total;
        pos = next_index + 1;
      }

      if (next_index == -1)
        break;
    }

    DBGWS("args count: %d\n", (int)arg_total);
    return arg_total;
  }


  bool _parseForm(ClientType& client, const String& boundary, uint32_t len);
  bool _parseFormUploadAborted();
  void _uploadWriteByte(uint8_t b){
    if (_currentUpload->currentSize == HTTP_UPLOAD_BUFLEN){
      if(_currentHandler && _currentHandler->canUpload(_currentUri))
        _currentHandler->upload(*this, _currentUri, *_currentUpload);
      _currentUpload->totalSize += _currentUpload->currentSize;
      _currentUpload->currentSize = 0;
    }
    _currentUpload->buf[_currentUpload->currentSize++] = b;
  }

  int _uploadReadByte(ClientType& client){
    int res = client.read();
    if(res == -1){
      while(!client.available() && client.connected())
        yield();
      res = client.read();
    }
    return res;
  }
  void _prepareHeader(String& response, int code, const char* content_type, size_t contentLength);
  bool _collectHeader(const char* headerName, const char* headerValue);

  void _streamFileCore(const size_t fileSize, const String & fileName, const String & contentType);

  static String _getRandomHexString();
  // for extracting Auth parameters
  String _extractParam(String& authReq,const String& param,const char delimit = '"') const;

  struct RequestArgument {
    String key;
    String value;
  };

  ServerType  _server;
  ClientType  _currentClient;
  HTTPMethod  _currentMethod = HTTP_ANY;
  String      _currentUri;
  uint8_t     _currentVersion = 0;
  HTTPClientStatus _currentStatus = HC_NONE;
  unsigned long _statusChange = 0;

  RequestHandlerType*  _currentHandler = nullptr;
  RequestHandlerType*  _firstHandler = nullptr;
  RequestHandlerType*  _lastHandler = nullptr;
  THandlerFunction _notFoundHandler;
  THandlerFunction _fileUploadHandler;

  int              _currentArgCount = 0;
  RequestArgument* _currentArgs = nullptr;
  int              _currentArgsHavePlain = 0;
  std::unique_ptr<HTTPUpload> _currentUpload;
  int              _postArgsLen = 0;
  RequestArgument* _postArgs = nullptr;

  int              _headerKeysCount = 0;
  RequestArgument* _currentHeaders = nullptr;

  size_t           _contentLength = 0;
  String           _responseHeaders;

  String           _hostHeader;
  bool             _chunked = false;
  bool             _corsEnabled = false;
  bool             _keepAlive = false;

  String           _snonce;  // Store noance and opaque for future comparison
  String           _sopaque;
  String           _srealm;  // Store the Auth realm between Calls

  HookFunction     _hook;
};


static const char AUTHORIZATION_HEADER[] PROGMEM = "Authorization";
static const char qop_auth[] PROGMEM = "qop=auth";
static const char qop_auth_quoted[] PROGMEM = "qop=\"auth\"";
static const char WWW_Authenticate[] PROGMEM = "WWW-Authenticate";
static const char Content_Length[] PROGMEM = "Content-Length";
static const char ETAG_HEADER[] PROGMEM = "If-None-Match";

class IPAddress {
    private:

        ip_addr_t _ip;

        // Access the raw byte array containing the address.  Because this returns a pointer
        // to the internal structure rather than a copy of the address this function should only
        // be used when you know that the usage of the returned uint8_t* will be transient and not
        // stored.
        uint8_t* raw_address() {
            return reinterpret_cast<uint8_t*>(&v4());
        }
        const uint8_t* raw_address() const {
            return reinterpret_cast<const uint8_t*>(&v4());
        }

        void ctor32 (uint32_t);

    public:
        // Constructors
        IPAddress();
        IPAddress(const IPAddress& from);
        IPAddress(uint8_t first_octet, uint8_t second_octet, uint8_t third_octet, uint8_t fourth_octet);
        IPAddress(uint32_t address) { ctor32(address); }
//        IPAddress(u32_t address) { ctor32(address); }
        IPAddress(int address) { ctor32(address); }
        IPAddress(const uint8_t *address);

        bool fromString(const char *address);
        bool fromString(const String &address) { return fromString(address.c_str()); }

        bool isSet () const;
        operator bool () const { return isSet(); } // <-
        operator bool ()       { return isSet(); } // <- both are needed
/*
        // Overloaded cast operator to allow IPAddress objects to be used where a pointer
        // to a four-byte uint8_t array is expected
        operator uint32_t() const { return isV4()? v4(): (uint32_t)0; }
        operator uint32_t()       { return isV4()? v4(): (uint32_t)0; }
        operator u32_t()    const { return isV4()? v4():    (u32_t)0; }
        operator u32_t()          { return isV4()? v4():    (u32_t)0; }

        // generic IPv4 wrapper to uint32-view like arduino loves to see it
        const u32_t& v4() const { return ip_2_ip4(&_ip)->addr; } // for raw_address(const)
              u32_t& v4()       { return ip_2_ip4(&_ip)->addr; }

        bool operator==(const IPAddress& addr) const {
            return ip_addr_cmp(&_ip, &addr._ip);
        }
        bool operator!=(const IPAddress& addr) const {
            return !ip_addr_cmp(&_ip, &addr._ip);
        }
        bool operator==(uint32_t addr) const {
            return isV4() && v4() == addr;
        }
        bool operator==(u32_t addr) const {
            return isV4() && v4() == addr;
        }
        bool operator!=(uint32_t addr) const {
            return !(isV4() && v4() == addr);
        }
        bool operator!=(u32_t addr) const {
            return !(isV4() && v4() == addr);
        }
        bool operator==(const uint8_t* addr) const;

        int operator>>(int n) const {
            return isV4()? v4() >> n: 0;
        }

        // Overloaded index operator to allow getting and setting individual octets of the address
        uint8_t operator[](int index) const {
            return isV4()? *(raw_address() + index): 0;
        }
        uint8_t& operator[](int index) {
            setV4();
            return *(raw_address() + index);
        }
*/
        // Overloaded copy operators to allow initialisation of IPAddress objects from other types
        IPAddress& operator=(const uint8_t *address);
        IPAddress& operator=(uint32_t address);
        IPAddress& operator=(const IPAddress&) = default;

        //virtual size_t printTo(Print& p) const;
        String toString() const;

        void clear();

        /*
                check if input string(arg) is a valid IPV4 address or not.
                return true on valid.
                return false on invalid.
        */
        static bool isValid(const String& arg);
        static bool isValid(const char* arg);

        friend class EthernetClass;
        friend class UDP;
        friend class Client;
        friend class Server;
        friend class DhcpClass;
        friend class DNSClient;

        /*
               lwIP address compatibility
        */
	   /*
        IPAddress(const ipv4_addr& fw_addr)   { setV4(); v4() = fw_addr.addr; }
        IPAddress(const ipv4_addr* fw_addr)   { setV4(); v4() = fw_addr->addr; }

        IPAddress& operator=(const ipv4_addr& fw_addr)   { setV4(); v4() = fw_addr.addr;  return *this; }
        IPAddress& operator=(const ipv4_addr* fw_addr)   { setV4(); v4() = fw_addr->addr; return *this; }

        operator       ip_addr_t () const { return  _ip; }
        operator const ip_addr_t*() const { return &_ip; }
        operator       ip_addr_t*()       { return &_ip; }

        bool isV4() const { return IP_IS_V4_VAL(_ip); }
        void setV4() { IP_SET_TYPE_VAL(_ip, IPADDR_TYPE_V4); }

        bool isLocal () const { return ip_addr_islinklocal(&_ip); }
*/
#if LWIP_IPV6

        IPAddress(const ip_addr_t& lwip_addr) { ip_addr_copy(_ip, lwip_addr); }
        IPAddress(const ip_addr_t* lwip_addr) { ip_addr_copy(_ip, *lwip_addr); }

        IPAddress& operator=(const ip_addr_t& lwip_addr) { ip_addr_copy(_ip, lwip_addr); return *this; }
        IPAddress& operator=(const ip_addr_t* lwip_addr) { ip_addr_copy(_ip, *lwip_addr); return *this; }

        uint16_t* raw6()
        {
            setV6();
            return reinterpret_cast<uint16_t*>(ip_2_ip6(&_ip));
        }

        const uint16_t* raw6() const
        {
            return isV6()? reinterpret_cast<const uint16_t*>(ip_2_ip6(&_ip)): nullptr;
        }

        // when not IPv6, ip_addr_t == ip4_addr_t so this one would be ambiguous
        // required otherwise
        operator const ip4_addr_t*() const { return isV4()? ip_2_ip4(&_ip): nullptr; }

        bool isV6() const { return IP_IS_V6_VAL(_ip); }
        void setV6() { IP_SET_TYPE_VAL(_ip, IPADDR_TYPE_V6); }

    protected:
        bool fromString6(const char *address);

#else

        // allow portable code when IPv6 is not enabled

        uint16_t* raw6() { return nullptr; }
        const uint16_t* raw6() const { return nullptr; }
        bool isV6() const { return false; }
        void setV6() { }

#endif

    protected:
        bool fromString4(const char *address);

};

template <typename ServerType>
ESP8266WebServerTemplate<ServerType>::ESP8266WebServerTemplate(IPAddress addr, int port)
: _server(addr, port)
{
}

template <typename ServerType>
ESP8266WebServerTemplate<ServerType>::ESP8266WebServerTemplate(int port)
: _server(port)
{
}

template <typename ServerType>
ESP8266WebServerTemplate<ServerType>::~ESP8266WebServerTemplate() {
  _server.close();
  if (_currentHeaders)
    delete[]_currentHeaders;
  RequestHandlerType* handler = _firstHandler;
  while (handler) {
    RequestHandlerType* next = handler->next();
    delete handler;
    handler = next;
  }
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::enableCORS(bool enable) {
  _corsEnabled = enable;
}
template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::begin() {
  close();
  _server.begin();
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::begin(uint16_t port) {
  close();
  _server.begin(port);
}

template <typename ServerType>
String ESP8266WebServerTemplate<ServerType>::_extractParam(String& authReq,const String& param,const char delimit) const {
  int _begin = authReq.find(param);
  if (_begin == -1)
    return emptyString;
  return authReq.substr(_begin+param.length(),authReq.find(delimit,_begin+param.length()));
}

template <typename ServerType>
bool ESP8266WebServerTemplate<ServerType>::authenticate(const char * username, const char * password){
  if(hasHeader(FPSTR(AUTHORIZATION_HEADER))) {
    String authReq = header(FPSTR(AUTHORIZATION_HEADER));
    if(authReq.startsWith(F("Basic"))){
      authReq = authReq.substr(6);
      authReq.trim();
      char toencodeLen = strlen(username)+strlen(password)+1;
      char *toencode = new (std::nothrow) char[toencodeLen + 1];
      if(toencode == NULL){
        authReq = "";
        return false;
      }
      sprintf(toencode, "%s:%s", username, password);
      String encoded = base64::encode((uint8_t *)toencode, toencodeLen, false);
      if(!encoded){
        authReq = "";
        delete[] toencode;
        return false;
      }
      if(authReq.equalsConstantTime(encoded)) {
        authReq = "";
        delete[] toencode;
        return true;
      }
      delete[] toencode;
    } else if(authReq.startsWith(F("Digest"))) {
      String _realm    = _extractParam(authReq, F("realm=\""));
      String _H1 = credentialHash((String)username,_realm,(String)password);
      return authenticateDigest((String)username,_H1);
    }
    authReq = "";
  }
  return false;
}

template <typename ServerType>
bool ESP8266WebServerTemplate<ServerType>::authenticateDigest(const String& username, const String& H1)
{
  if(hasHeader(FPSTR(AUTHORIZATION_HEADER))) {
    String authReq = header(FPSTR(AUTHORIZATION_HEADER));
    if(authReq.startsWith(F("Digest"))) {
      authReq = authReq.substr(7);
      DBGWS("%s\n", authReq.c_str());
      String _username = _extractParam(authReq,F("username=\""));
      if(!_username.length() || _username != String(username)) {
        authReq = "";
        return false;
      }
      // extracting required parameters for RFC 2069 simpler Digest
      String _realm    = _extractParam(authReq, F("realm=\""));
      String _nonce    = _extractParam(authReq, F("nonce=\""));
      String _uri      = _extractParam(authReq, F("uri=\""));
      String _response = _extractParam(authReq, F("response=\""));
      String _opaque   = _extractParam(authReq, F("opaque=\""));

      if((!_realm.length()) || (!_nonce.length()) || (!_uri.length()) || (!_response.length()) || (!_opaque.length())) {
        authReq = "";
        return false;
      }
      if((_opaque != _sopaque) || (_nonce != _snonce) || (_realm != _srealm)) {
        authReq = "";
        return false;
      }
      // parameters for the RFC 2617 newer Digest
      String _nc,_cnonce;
      if(authReq.find(FPSTR(qop_auth)) != -1 || authReq.find(FPSTR(qop_auth_quoted)) != -1) {
        _nc = _extractParam(authReq, F("nc="), ',');
        _cnonce = _extractParam(authReq, F("cnonce=\""));
      }
      DBGWS("Hash of user:realm:pass=%s\n", H1.c_str());
      MD5Builder md5;
      md5.begin();
      if(_currentMethod == HTTP_GET){
        md5.add(String(F("GET:")) + _uri);
      }else if(_currentMethod == HTTP_POST){
        md5.add(String(F("POST:")) + _uri);
      }else if(_currentMethod == HTTP_PUT){
        md5.add(String(F("PUT:")) + _uri);
      }else if(_currentMethod == HTTP_DELETE){
        md5.add(String(F("DELETE:")) + _uri);
      }else{
        md5.add(String(F("GET:")) + _uri);
      }
      md5.calculate();
      String _H2 = md5.toString();
      DBGWS("Hash of GET:uri=%s\n", _H2.c_str());
      md5.begin();
      if(authReq.find(FPSTR(qop_auth)) != -1 || authReq.find(FPSTR(qop_auth_quoted)) != -1) {
        md5.add(H1 + ':' + _nonce + ':' + _nc + ':' + _cnonce + F(":auth:") + _H2);
      } else {
        md5.add(H1 + String(':') + _nonce + String(':') + _H2);
      }
      md5.calculate();
      String _responsecheck = md5.toString();
      DBGWS("The Proper response=%s\n", _responsecheck.c_str());
      if(_response == _responsecheck){
        authReq = "";
        return true;
      }
    }
    authReq = "";
  }
  return false;
}

template <typename ServerType>
String ESP8266WebServerTemplate<ServerType>::_getRandomHexString() {
  char buffer[33];  // buffer to hold 32 Hex Digit + /0
  int i;
  for(i = 0; i < 4; i++) {
    sprintf (buffer + (i*8), "%08x", RANDOM_REG32);
  }
  return String(buffer);
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::requestAuthentication(HTTPAuthMethod mode, const char* realm, const String& authFailMsg) {
  if(realm == NULL) {
    _srealm = String(F("Login Required"));
  } else {
    _srealm = String(realm);
  }
  if(mode == BASIC_AUTH) {
    sendHeader(String(FPSTR(WWW_Authenticate)), String(F("Basic realm=\"")) + _srealm + String('\"'));
  } else {
    _snonce=_getRandomHexString();
    _sopaque=_getRandomHexString();
    sendHeader(String(FPSTR(WWW_Authenticate)), String(F("Digest realm=\"")) +_srealm + String(F("\", qop=\"auth\", nonce=\"")) + _snonce + String(F("\", opaque=\"")) + _sopaque + String('\"'));
  }
  using namespace mime;
  send(401, String(FPSTR(mimeTable[html].mimeType)), authFailMsg);
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::on(const Uri &uri, ESP8266WebServerTemplate<ServerType>::THandlerFunction handler) {
  on(uri, HTTP_ANY, handler);
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::on(const Uri &uri, HTTPMethod method, ESP8266WebServerTemplate<ServerType>::THandlerFunction fn) {
  on(uri, method, fn, _fileUploadHandler);
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::on(const Uri &uri, HTTPMethod method, ESP8266WebServerTemplate<ServerType>::THandlerFunction fn, ESP8266WebServerTemplate<ServerType>::THandlerFunction ufn) {
  _addRequestHandler(new FunctionRequestHandler<ServerType>(fn, ufn, uri, method));
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::addHandler(RequestHandlerType* handler) {
    _addRequestHandler(handler);
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::_addRequestHandler(RequestHandlerType* handler) {
    if (!_lastHandler) {
      _firstHandler = handler;
      _lastHandler = handler;
    }
    else {
      _lastHandler->next(handler);
      _lastHandler = handler;
    }
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::serveStatic(const char* uri, FS& fs, const char* path, const char* cache_header) {
  bool is_file = false;

  if (fs.exists(path)) {
    File file = fs.open(path, "r");
    is_file = file && file.isFile();
    file.close();
  }

  if(is_file)
    _addRequestHandler(new StaticFileRequestHandler<ServerType>(fs, path, uri, cache_header));
  else
    _addRequestHandler(new StaticDirectoryRequestHandler<ServerType>(fs, path, uri, cache_header));  
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::handleClient() {
  if (_currentStatus == HC_NONE) {
    ClientType client = _server.available();
    if (!client) {
      return;
    }

    DBGWS("New client\n");

    _currentClient = client;
    _currentStatus = HC_WAIT_READ;
    _statusChange = millis();
  }

  bool keepCurrentClient = false;
  bool callYield = false;

  DBGWS("http-server loop: conn=%d avail=%d status=%s\n",
    _currentClient.connected(), _currentClient.available(),
    _currentStatus==HC_NONE?"none":
    _currentStatus==HC_WAIT_READ?"wait-read":
    _currentStatus==HC_WAIT_CLOSE?"wait-close":
    "??");

  if (_currentClient.connected() || _currentClient.available()) {
    if (_currentClient.available() && _keepAlive) {
      _currentStatus = HC_WAIT_READ;
    }

    switch (_currentStatus) {
    case HC_NONE:
      // No-op to avoid C++ compiler warning
      break;
    case HC_WAIT_READ:
      // Wait for data from client to become available
      if (_currentClient.available()) {
        switch (_parseRequest(_currentClient))
        {
        case CLIENT_REQUEST_CAN_CONTINUE:
          _currentClient.setTimeout(HTTP_MAX_SEND_WAIT);
          _contentLength = CONTENT_LENGTH_NOT_SET;
          _handleRequest();
          /* fallthrough */
        case CLIENT_REQUEST_IS_HANDLED:
          if (_currentClient.connected() || _currentClient.available()) {
            _currentStatus = HC_WAIT_CLOSE;
            _statusChange = millis();
            keepCurrentClient = true;
          }
          else
            DBGWS("webserver: peer has closed after served\n");
          break;
        case CLIENT_MUST_STOP:
          DBGWS("Close client\n");
          _currentClient.stop();
          break;
        case CLIENT_IS_GIVEN:
          // client must not be stopped but must not be handled here anymore
          // (example: tcp connection given to websocket)
          DBGWS("Give client\n");
          break;
        } // switch _parseRequest()
      } else {
        // !_currentClient.available(): waiting for more data
        if (millis() - _statusChange <= HTTP_MAX_DATA_WAIT) {
          keepCurrentClient = true;
        }
        else
          DBGWS("webserver: closing after read timeout\n");
        callYield = true;
      }
      break;
    case HC_WAIT_CLOSE:
      // Wait for client to close the connection
      if (!_server.hasClient() && (millis() - _statusChange <= HTTP_MAX_CLOSE_WAIT)) {
        keepCurrentClient = true;
        callYield = true;
        if (_currentClient.available())
            // continue serving current client
            _currentStatus = HC_WAIT_READ;
      }
      break;
    } // switch _currentStatus
  }

  if (!keepCurrentClient) {
    DBGWS("Drop client\n");
    _currentClient = ClientType();
    _currentStatus = HC_NONE;
    _currentUpload.reset();
  }

  if (callYield) {
    yield();
  }
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::close() {
  _server.close();
  _currentStatus = HC_NONE;
  if(!_headerKeysCount)
    collectHeaders();
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::stop() {
  close();
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::sendHeader(const String& name, const String& value, bool first) {
  String headerLine = name;
  headerLine += F(": ");
  headerLine += value;
  headerLine += "\r\n";

  if (first) {
    _responseHeaders = headerLine + _responseHeaders;
  }
  else {
    _responseHeaders += headerLine;
  }
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::setContentLength(const size_t contentLength) {
    _contentLength = contentLength;
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::_prepareHeader(String& response, int code, const char* content_type, size_t contentLength) {
    response = String(F("HTTP/1.")) + String(_currentVersion) + String(' ');
    response += String(code);
    response += ' ';
    response += responseCodeToString(code);
    response += "\r\n";

    using namespace mime;
    if (!content_type)
        content_type = mimeTable[html].mimeType;

    sendHeader(String(F("Content-Type")), String(FPSTR(content_type)), true);
    if (_contentLength == CONTENT_LENGTH_NOT_SET) {
        sendHeader(String(FPSTR(Content_Length)), String(contentLength));
    } else if (_contentLength != CONTENT_LENGTH_UNKNOWN) {
        sendHeader(String(FPSTR(Content_Length)), String(_contentLength));
    } else if(_contentLength == CONTENT_LENGTH_UNKNOWN && _currentVersion){ //HTTP/1.1 or above client
      //let's do chunked
      _chunked = true;
      sendHeader(String(F("Accept-Ranges")),String(F("none")));
      sendHeader(String(F("Transfer-Encoding")),String(F("chunked")));
    }
    if (_corsEnabled) {
      sendHeader(String(F("Access-Control-Allow-Origin")), String("*"));
    }

    if (_keepAlive && _server.hasClient()) { // Disable keep alive if another client is waiting.
      _keepAlive = false;
    }
    sendHeader(String(F("Connection")), String(_keepAlive ? F("keep-alive") : F("close")));
    if (_keepAlive) {
      sendHeader(String(F("Keep-Alive")), String(F("timeout=")) + String(HTTP_MAX_CLOSE_WAIT));
    }

    response += _responseHeaders;
    response += "\r\n";
    _responseHeaders = "";
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::send(int code, char* content_type, const String& content) {
  return send(code, (const char*)content_type, content);
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::send(int code, const char* content_type, const String& content) {
  return send(code, content_type, content.c_str(), content.length());
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::send(int code, const String& content_type, const String& content) {
  return send(code, (const char*)content_type.c_str(), content);
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::sendContent(const String& content) {
  StreamConstPtr ref(content.c_str(), content.length());
  sendContent(&ref);
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::send(int code, const char* content_type, Stream* stream, size_t content_length /*= 0*/) {
  String header;
  if (content_length == 0)
      content_length = std::max((ssize_t)0, stream->streamRemaining());
  _prepareHeader(header, code, content_type, content_length);
  size_t sent = StreamConstPtr(header).sendAll(&_currentClient);
  if (sent != header.length())
      DBGWS("HTTPServer: error: sent %zd on %u bytes\n", sent, header.length());
  if (content_length)
    return sendContent(stream, content_length);
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::send_P(int code, PGM_P content_type, PGM_P content) {
  StreamConstPtr ref(content, strlen_P(content));
  return send(code, String(content_type).c_str(), &ref);
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::send_P(int code, PGM_P content_type, PGM_P content, size_t contentLength) {
  StreamConstPtr ref(content, contentLength);
  return send(code, String(content_type).c_str(), &ref);
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::sendContent(Stream* content, ssize_t content_length /* = 0*/) {
  if (_currentMethod == HTTP_HEAD)
    return;
  if (content_length <= 0)
    content_length = std::max((ssize_t)0, content->streamRemaining());
  if(_chunked) {
    _currentClient.printf("%zx\r\n", content_length);
  }
  ssize_t sent = content->sendSize(&_currentClient, content_length);
  if (sent != content_length)
  {
    DBGWS("HTTPServer: error: short send after timeout (%d<%d)\n", sent, content_length);
  }
  if(_chunked) {
    _currentClient.printf_P(PSTR("\r\n"));
    if (content_length == 0) {
      _chunked = false;
    }
  }
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::sendContent_P(PGM_P content) {
  sendContent_P(content, strlen_P(content));
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::sendContent_P(PGM_P content, size_t size) {
  StreamConstPtr ptr(content, size);
  return sendContent(&ptr, size);
}

template <typename ServerType>
String ESP8266WebServerTemplate<ServerType>::credentialHash(const String& username, const String& realm, const String& password)
{
  MD5Builder md5;
  md5.begin();
  md5.add(username + String(':') + realm + String(':') + password);  // md5 of the user:realm:password
  md5.calculate();
  return md5.toString();
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::_streamFileCore(const size_t fileSize, const String &fileName, const String &contentType)
{
  using namespace mime;
  setContentLength(fileSize);
  if (fileName.endsWith(String(FPSTR(mimeTable[gz].endsWith))) &&
      contentType != String(FPSTR(mimeTable[gz].mimeType)) &&
      contentType != String(FPSTR(mimeTable[none].mimeType))) {
    sendHeader(F("Content-Encoding"), F("gzip"));
  }
  send(200, contentType, emptyString);
}

template <typename ServerType>
const String& ESP8266WebServerTemplate<ServerType>::pathArg(unsigned int i) const {
  if (_currentHandler != nullptr)
    return _currentHandler->pathArg(i);
  return emptyString;
}

template <typename ServerType>
const String& ESP8266WebServerTemplate<ServerType>::arg(const String& name) const {
  for (int j = 0; j < _postArgsLen; ++j) {
    if ( _postArgs[j].key == name )
      return _postArgs[j].value;
  }
  for (int i = 0; i < _currentArgCount + _currentArgsHavePlain; ++i) {
    if ( _currentArgs[i].key == name )
      return _currentArgs[i].value;
  }
  return emptyString;
}

template <typename ServerType>
const String& ESP8266WebServerTemplate<ServerType>::arg(int i) const {
  if (i >= 0 && i < _currentArgCount + _currentArgsHavePlain)
    return _currentArgs[i].value;
  return emptyString;
}

template <typename ServerType>
const String& ESP8266WebServerTemplate<ServerType>::argName(int i) const {
  if (i >= 0 && i < _currentArgCount + _currentArgsHavePlain)
    return _currentArgs[i].key;
  return emptyString;
}

template <typename ServerType>
int ESP8266WebServerTemplate<ServerType>::args() const {
  return _currentArgCount;
}

template <typename ServerType>
bool ESP8266WebServerTemplate<ServerType>::hasArg(const String& name) const {
  for (int j = 0; j < _postArgsLen; ++j) {
    if (_postArgs[j].key == name)
      return true;
  }
  for (int i = 0; i < _currentArgCount + _currentArgsHavePlain; ++i) {
    if (_currentArgs[i].key == name)
      return true;
  }
  return false;
}

template <typename ServerType>
const String& ESP8266WebServerTemplate<ServerType>::header(const String& name) const {
  for (int i = 0; i < _headerKeysCount; ++i) {
    if (equalsIgnoreCase(_currentHeaders[i].key, name))
      return _currentHeaders[i].value;
  }
  return emptyString;
}

template<typename ServerType>
void ESP8266WebServerTemplate<ServerType>::collectHeaders(const char* headerKeys[], const size_t headerKeysCount) {
  if (_currentHeaders)
    delete[] _currentHeaders;
  _currentHeaders = new RequestArgument[_headerKeysCount = headerKeysCount + 2];
  _currentHeaders[0].key = FPSTR(AUTHORIZATION_HEADER);
  _currentHeaders[1].key = FPSTR(ETAG_HEADER);
  for (int i = 2; i < _headerKeysCount; i++){
      _currentHeaders[i].key = headerKeys[i - 2];
  }
}

template <typename ServerType>
template <typename... Args>
void ESP8266WebServerTemplate<ServerType>::collectHeaders(const Args&... args) {
  if (_currentHeaders)
    delete[] _currentHeaders;
  _currentHeaders = new RequestArgument[_headerKeysCount = sizeof...(args) + 2] {
    { .key = FPSTR(AUTHORIZATION_HEADER), .value = emptyString },
    { .key = FPSTR(ETAG_HEADER), .value = emptyString },
    { .key = args, .value = emptyString } ...
  };
}

template <typename ServerType>
const String& ESP8266WebServerTemplate<ServerType>::header(int i) const {
  if (i < _headerKeysCount)
    return _currentHeaders[i].value;
  return emptyString;
}

template <typename ServerType>
const String& ESP8266WebServerTemplate<ServerType>::headerName(int i) const {
  if (i < _headerKeysCount)
    return _currentHeaders[i].key;
  return emptyString;
}

template <typename ServerType>
int ESP8266WebServerTemplate<ServerType>::headers() const {
  return _headerKeysCount;
}

template <typename ServerType>
bool ESP8266WebServerTemplate<ServerType>::hasHeader(const String& name) const {
  for (int i = 0; i < _headerKeysCount; ++i) {
    if ((equalsIgnoreCase(_currentHeaders[i].key, name)) &&  (_currentHeaders[i].value.length() > 0))
      return true;
  }
  return false;
}

template <typename ServerType>
const String& ESP8266WebServerTemplate<ServerType>::hostHeader() const {
  return _hostHeader;
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::onFileUpload(THandlerFunction fn) {
  _fileUploadHandler = fn;
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::onNotFound(THandlerFunction fn) {
  _notFoundHandler = fn;
}

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::_handleRequest() {
  bool handled = false;
  if (!_currentHandler){
    DBGWS("request handler not found\n");
  }
  else {
    handled = _currentHandler->handle(*this, _currentMethod, _currentUri);
    if (!handled) {
      DBGWS("request handler failed to handle request\n");
    }
  }
  if (!handled && _notFoundHandler) {
    _notFoundHandler();
    handled = true;
  }
  if (!handled) {
    using namespace mime;
    send(404, FPSTR(mimeTable[html].mimeType), String(F("Not found: ")) + _currentUri);
    handled = true;
  }
  if (handled) {
    _finalizeResponse();
  }
  _currentUri = "";
}


template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::_finalizeResponse() {
  if (_chunked) {
    sendContent(emptyString);
  }
}

template <typename ServerType>
String ESP8266WebServerTemplate<ServerType>::responseCodeToString(const int code) {
    // By first determining the pointer to the flash stored string in the switch
    // statement and then doing String(FlashStringHelper) return reduces the total code
    // size of this function by over 50%.
    const __FlashStringHelper *r;
    switch (code)
    {
    case 100:
        r = F("Continue");
        break;
    case 101:
        r = F("Switching Protocols");
        break;
    case 200:
        r = F("OK");
        break;
    case 201:
        r = F("Created");
        break;
    case 202:
        r = F("Accepted");
        break;
    case 203:
        r = F("Non-Authoritative Information");
        break;
    case 204:
        r = F("No Content");
        break;
    case 205:
        r = F("Reset Content");
        break;
    case 206:
        r = F("Partial Content");
        break;
    case 300:
        r = F("Multiple Choices");
        break;
    case 301:
        r = F("Moved Permanently");
        break;
    case 302:
        r = F("Found");
        break;
    case 303:
        r = F("See Other");
        break;
    case 304:
        r = F("Not Modified");
        break;
    case 305:
        r = F("Use Proxy");
        break;
    case 307:
        r = F("Temporary Redirect");
        break;
    case 400:
        r = F("Bad Request");
        break;
    case 401:
        r = F("Unauthorized");
        break;
    case 402:
        r = F("Payment Required");
        break;
    case 403:
        r = F("Forbidden");
        break;
    case 404:
        r = F("Not Found");
        break;
    case 405:
        r = F("Method Not Allowed");
        break;
    case 406:
        r = F("Not Acceptable");
        break;
    case 407:
        r = F("Proxy Authentication Required");
        break;
    case 408:
        r = F("Request Timeout");
        break;
    case 409:
        r = F("Conflict");
        break;
    case 410:
        r = F("Gone");
        break;
    case 411:
        r = F("Length Required");
        break;
    case 412:
        r = F("Precondition Failed");
        break;
    case 413:
        r = F("Request Entity Too Large");
        break;
    case 414:
        r = F("URI Too Long");
        break;
    case 415:
        r = F("Unsupported Media Type");
        break;
    case 416:
        r = F("Range not satisfiable");
        break;
    case 417:
        r = F("Expectation Failed");
        break;
    case 500:
        r = F("Internal Server Error");
        break;
    case 501:
        r = F("Not Implemented");
        break;
    case 502:
        r = F("Bad Gateway");
        break;
    case 503:
        r = F("Service Unavailable");
        break;
    case 504:
        r = F("Gateway Timeout");
        break;
    case 505:
        r = F("HTTP Version not supported");
        break;
    default:
        r = F("");
        break;
    }
    return String(r);
}



#ifndef WEBSERVER_MAX_POST_ARGS
#define WEBSERVER_MAX_POST_ARGS 32
#endif

static const char Content_Type[] PROGMEM = "Content-Type";
static const char filename[] PROGMEM = "filename";

template <typename ServerType>
static bool readBytesWithTimeout(typename ServerType::ClientType& client, size_t maxLength, String& data, int timeout_ms)
{
  S2Stream dataStream(data);
  return client.sendSize(dataStream, maxLength, timeout_ms) == maxLength;
}

inline bool equalsIgnoreCase(const char *s1, const char *s2){
  if (!s1 && s2) return false;
  if (s1  && !s2) return  false;
  if (!s1  && !s2) return false;
  
  while(1) {
    char c1 = toupper(*s1);
    char c2 = toupper(*s2)
    if( c1 < c2 ) return false;
    if( c1 > c2 ) return false;
    if( c1 == '\0') return true;
    ++s1; ++s2;
  }
}
inline bool equalsIgnoreCase(const String& s1, const char *s2){
  return equalsIgnoreCase(s1.c_str(), s2);
}
inline bool startsWith(const String& s1, const char * s2){
  if (!s2) return false;
  return s.rfind(s2, 0) == 0;
}

template <typename ServerType>
typename ESP8266WebServerTemplate<ServerType>::ClientFuture ESP8266WebServerTemplate<ServerType>::_parseRequest(ClientType& client) {
  // Read the first line of HTTP request
  String req = client.readStringUntil('\r');
  DBGWS("request: %s\n", req.c_str());
  client.readStringUntil('\n');
  //reset header value
  for (int i = 0; i < _headerKeysCount; ++i) {
    _currentHeaders[i].value.clear();
   }

  // First line of HTTP request looks like "GET /path HTTP/1.1"
  // Retrieve the "/path" part by finding the spaces
  int addr_start = req.find(' ');
  int addr_end = req.find(' ', addr_start + 1);
  if (addr_start == -1 || addr_end == -1) {
    DBGWS("Invalid request\n");
    return CLIENT_MUST_STOP;
  }

  String methodStr = req.substr(0, addr_start);
  String url = req.substr(addr_start + 1, addr_end);
  String versionEnd = req.substr(addr_end + 8);
  _currentVersion = atoi(versionEnd.c_str());
  String searchStr;
  int hasSearch = url.find('?');
  if (hasSearch != -1){
    searchStr = url.substr(hasSearch + 1);
    url = url.substr(0, hasSearch);
  }
  _currentUri = url;
  _chunked = false;

  if (_hook)
  {
    auto whatNow = _hook(methodStr, url, &client, mime::getContentType);
    if (whatNow != CLIENT_REQUEST_CAN_CONTINUE)
        return whatNow;
  }

  HTTPMethod method = HTTP_GET;
  if (methodStr == F("HEAD")) {
    method = HTTP_HEAD;
  } else if (methodStr == F("POST")) {
    method = HTTP_POST;
  } else if (methodStr == F("DELETE")) {
    method = HTTP_DELETE;
  } else if (methodStr == F("OPTIONS")) {
    method = HTTP_OPTIONS;
  } else if (methodStr == F("PUT")) {
    method = HTTP_PUT;
  } else if (methodStr == F("PATCH")) {
    method = HTTP_PATCH;
  }
  _currentMethod = method;

  _keepAlive = _currentVersion > 0; // Keep the connection alive by default
                                    // if the protocol version is greater than HTTP 1.0

  DBGWS("method: %s url: %s search: %s keepAlive=: %d\n",
      methodStr.c_str(), url.c_str(), searchStr.c_str(), _keepAlive);

  //attach handler
  RequestHandlerType* handler;
  for (handler = _firstHandler; handler; handler = handler->next()) {
    if (handler->canHandle(_currentMethod, _currentUri))
      break;
  }
  _currentHandler = handler;

  String formData;
  // below is needed only when POST type request
  if (method == HTTP_POST || method == HTTP_PUT || method == HTTP_PATCH || method == HTTP_DELETE){
    String boundaryStr;
    String headerName;
    String headerValue;
    bool isForm = false;
    bool isEncoded = false;
    uint32_t contentLength = 0;
    //parse headers
    while(1){
      req = client.readStringUntil('\r');
      client.readStringUntil('\n');
      if (req.empty()) break; //no more headers
      int headerDiv = req.find(':');
      if (headerDiv == -1){
        break;
      }
      headerName = req.substr(0, headerDiv);
      headerValue = req.substr(headerDiv + 1);
      headerValue.trim();
       _collectHeader(headerName.c_str(),headerValue.c_str());

      DBGWS("headerName: %s\nheaderValue: %s\n", headerName.c_str(), headerValue.c_str());

      if (equalsIgnoreCase(headerName, FPSTR(Content_Type))){
        using namespace mime;
        if (startsWith(headerValue, FPSTR(mimeTable[txt].mimeType))){
          isForm = false;
        } else if (startsWith(headerValue, F("application/x-www-form-urlencoded"))){
          isForm = false;
          isEncoded = true;
        } else if (startsWith(headerValue, F("multipart/"))){
          boundaryStr = headerValue.substr(headerValue.find('=') + 1);
          boundaryStr.replace("\"","");
          isForm = true;
        }
      } else if (equalsIgnoreCase(headerName, F("Content-Length"))){
        contentLength = std::stoi(headerValue);
      } else if (equalsIgnoreCase(headerName, F("Host"))){
        _hostHeader = headerValue;
      } else if (equalsIgnoreCase(headerName, F("Connection"))){
        _keepAlive = equalsIgnoreCase(headerValue, F("keep-alive"));
      }
    }

    String plainBuf;
    if (   !isForm
        && // read content into plainBuf
           (   !readBytesWithTimeout<ServerType>(client, contentLength, plainBuf, HTTP_MAX_POST_WAIT)
            || (plainBuf.length() < contentLength)
           )
       )
    {
        return CLIENT_MUST_STOP;
    }

    if (isEncoded) {
        // isEncoded => !isForm => plainBuf is not empty
        // add plainBuf in search str
        if (searchStr.length())
          searchStr += '&';
        searchStr += plainBuf;
    }

    // parse searchStr for key/value pairs
    _parseArguments(searchStr);

    if (!isForm) {
      if (contentLength) {
        // add key=value: plain={body} (post json or other data)
        RequestArgument& arg = _currentArgs[_currentArgCount++];
        arg.key = F("plain");
        arg.value = plainBuf;
        _currentArgsHavePlain = 1;
      }
    } else { // isForm is true
      // here: content is not yet read (plainBuf is still empty)
      if (!_parseForm(client, boundaryStr, contentLength)) {
        return CLIENT_MUST_STOP;
      }
    }
  } else {
    String headerName;
    String headerValue;
    //parse headers
    while(1){
      req = client.readStringUntil('\r');
      client.readStringUntil('\n');
      if (req.empty()) break;//no moar headers
      int headerDiv = req.find(':');
      if (headerDiv == -1){
        break;
      }
      headerName = req.substr(0, headerDiv);
      headerValue = req.substr(headerDiv + 2);
      _collectHeader(headerName.c_str(),headerValue.c_str());

      DBGWS("headerName: %s\nheaderValue: %s\n", headerName.c_str(), headerValue.c_str());

      if (equalsIgnoreCase(headerName, F("Host"))){
        _hostHeader = headerValue;
      } else if (equalsIgnoreCase(headerName, F("Connection"))){
        _keepAlive = equalsIgnoreCase(headerValue, F("keep-alive"));
      }
    }
    _parseArguments(searchStr);
  }
  client.flush();

#ifdef DEBUG_ESP_HTTP_SERVER
  DBGWS("Request: %s\nArguments: %s\nfinal list of key/value pairs:\n",
    url.c_str(), searchStr.c_str());
  for (int i = 0; i < _currentArgCount; i++)
    DBGWS("  key:'%s' value:'%s'\r\n",
      _currentArgs[i].key.c_str(),
      _currentArgs[i].value.c_str());
#endif

  return CLIENT_REQUEST_CAN_CONTINUE;
}

template <typename ServerType>
bool ESP8266WebServerTemplate<ServerType>::_collectHeader(const char* headerName, const char* headerValue) {
  for (int i = 0; i < _headerKeysCount; i++) {
    if (equalsIgnoreCase(_currentHeaders[i].key, headerName)) {
            _currentHeaders[i].value=headerValue;
            return true;
        }
  }
  return false;
}

template <typename ServerType>
struct storeArgHandler
{
  void operator() (String& key, String& value, const String& data, int equal_index, int pos, int key_end_pos, int next_index)
  {
    key = ESP8266WebServerTemplate<ServerType>::urlDecode(data.substr(pos, key_end_pos));
    if ((equal_index != -1) && ((equal_index < next_index - 1) || (next_index == -1)))
      value = ESP8266WebServerTemplate<ServerType>::urlDecode(data.substr(equal_index + 1, next_index));
  }
};

struct nullArgHandler
{
  void operator() (String& key, String& value, const String& data, int equal_index, int pos, int key_end_pos, int next_index) {
    (void)key; (void)value; (void)data; (void)equal_index; (void)pos; (void)key_end_pos; (void)next_index;
    // do nothing
  }
};

template <typename ServerType>
void ESP8266WebServerTemplate<ServerType>::_parseArguments(const String& data) {
  if (_currentArgs)
    delete[] _currentArgs;

  _currentArgCount = _parseArgumentsPrivate(data, nullArgHandler());

  // allocate one more, this is needed because {"plain": plainBuf} is always added
  _currentArgs = new RequestArgument[_currentArgCount + 1];

  (void)_parseArgumentsPrivate(data, storeArgHandler<ServerType>());
}

template <typename ServerType>
bool ESP8266WebServerTemplate<ServerType>::_parseForm(ClientType& client, const String& boundary, uint32_t len){
  (void) len;
  DBGWS("Parse Form: Boundary: '%s' Length: %d\n", boundary.c_str(), (int)len);
  String line;
  int retry = 0;
  do {
    line = client.readStringUntil('\r');
    ++retry;
  } while (line.length() == 0 && retry < 3);

  client.readStringUntil('\n');
  //start reading the form
  if (line == ("--"+boundary)){
    if(_postArgs) delete[] _postArgs;
    _postArgs = new RequestArgument[WEBSERVER_MAX_POST_ARGS];
    _postArgsLen = 0;
    while(1){
      String argName;
      String argValue;
      String argType;
      String argFilename;
      bool argIsFile = false;

      line = client.readStringUntil('\r');
      client.readStringUntil('\n');
      if (line.length() > 19 && equalsIgnoreCase(line.substr(0, 19), F("Content-Disposition"))){
        int nameStart = line.find('=');
        if (nameStart != -1){
          argName = line.substr(nameStart+2);
          nameStart = argName.find('=');
          if (nameStart == -1){
            argName = argName.substr(0, argName.length() - 1);
          } else {
            argFilename = argName.substr(nameStart+2, argName.length() - 1);
            argName = argName.substr(0, argName.find('"'));
            argIsFile = true;
            DBGWS("PostArg FileName: %s\n", argFilename.c_str());
            //use GET to set the filename if uploading using blob
            if (argFilename == F("blob") && hasArg(filename))
              argFilename = arg(FPSTR(filename));
          }
          DBGWS("PostArg Name: %s\n", argName.c_str());
          using namespace mime;
          argType = FPSTR(mimeTable[txt].mimeType);
          line = client.readStringUntil('\r');
          client.readStringUntil('\n');
          if (line.length() > 12 && equalsIgnoreCase(line.substr(0, 12), FPSTR(Content_Type))){
            argType = line.substr(line.find(':')+2);
            //skip next line
            client.readStringUntil('\r');
            client.readStringUntil('\n');
          }
          DBGWS("PostArg Type: %s\n", argType.c_str());
          if (!argIsFile){
            while(1){
              line = client.readStringUntil('\r');
              client.readStringUntil('\n');
              if (startsWith(line, "--"+boundary)) break;
              if (argValue.length() > 0) argValue += '\n';
              argValue += line;
            }
            DBGWS("PostArg Value: %s\n\n", argValue.c_str());

            RequestArgument& arg = _postArgs[_postArgsLen++];
            arg.key = argName;
            arg.value = argValue;

            if (line == ("--"+boundary+"--")){
              DBGWS("Done Parsing POST\n");
              break;
            }
          } else {
            _currentUpload.reset(new HTTPUpload());
            _currentUpload->status = UPLOAD_FILE_START;
            _currentUpload->name = argName;
            _currentUpload->filename = argFilename;
            _currentUpload->type = argType;
            _currentUpload->totalSize = 0;
            _currentUpload->currentSize = 0;
            _currentUpload->contentLength = len;
            DBGWS("Start File: %s Type: %s\n", _currentUpload->filename.c_str(), _currentUpload->type.c_str());
            if(_currentHandler && _currentHandler->canUpload(_currentUri))
              _currentHandler->upload(*this, _currentUri, *_currentUpload);
            _currentUpload->status = UPLOAD_FILE_WRITE;

            int fastBoundaryLen = 4 /* \r\n-- */ + boundary.length() + 1 /* \0 */;
            char fastBoundary[ fastBoundaryLen ];
            snprintf(fastBoundary, fastBoundaryLen, "\r\n--%s", boundary.c_str());
            int boundaryPtr = 0;
            while ( true ) {
                int ret = _uploadReadByte(client);
                if (ret < 0) {
                    // Unexpected, we should have had data available per above
                    return _parseFormUploadAborted();
                }
                char in = (char) ret;
                if (in == fastBoundary[ boundaryPtr ]) {
                    // The input matched the current expected character, advance and possibly exit this file
                    boundaryPtr++;
                    if (boundaryPtr == fastBoundaryLen - 1) {
                        // We read the whole boundary line, we're done here!
                        break;
                    }
                } else {
                    // The char doesn't match what we want, so dump whatever matches we had, the read in char, and reset ptr to start
                    for (int i = 0; i < boundaryPtr; i++) {
                        _uploadWriteByte( fastBoundary[ i ] );
                    }
                    if (in == fastBoundary[ 0 ]) {
                       // This could be the start of the real end, mark it so and don't emit/skip it
                       boundaryPtr = 1;
                    } else {
                      // Not the 1st char of our pattern, so emit and ignore
                      _uploadWriteByte( in );
                      boundaryPtr = 0;
                    }
                }
            }
            // Found the boundary string, finish processing this file upload
            if (_currentHandler && _currentHandler->canUpload(_currentUri))
                _currentHandler->upload(*this, _currentUri, *_currentUpload);
            _currentUpload->totalSize += _currentUpload->currentSize;
            _currentUpload->status = UPLOAD_FILE_END;
            if (_currentHandler && _currentHandler->canUpload(_currentUri))
                _currentHandler->upload(*this, _currentUri, *_currentUpload);
            DBGWS("End File: %s Type: %s Size: %d\n",
                _currentUpload->filename.c_str(),
                _currentUpload->type.c_str(),
                (int)_currentUpload->totalSize);
            if (!client.connected()) return _parseFormUploadAborted();
            line = client.readStringUntil('\r');
            client.readStringUntil('\n');
            if (line == "--") {     // extra two dashes mean we reached the end of all form fields
                DBGWS("Done Parsing POST\n");
                break;
            }
            continue;
          }
        }
      }
    }

    int iarg;
    int totalArgs = ((WEBSERVER_MAX_POST_ARGS - _postArgsLen) < _currentArgCount)?(WEBSERVER_MAX_POST_ARGS - _postArgsLen):_currentArgCount;
    for (iarg = 0; iarg < totalArgs; iarg++){
      RequestArgument& arg = _postArgs[_postArgsLen++];
      arg.key = _currentArgs[iarg].key;
      arg.value = _currentArgs[iarg].value;
    }
    if (_currentArgs) delete[] _currentArgs;
    _currentArgs = new RequestArgument[_postArgsLen];
    for (iarg = 0; iarg < _postArgsLen; iarg++){
      RequestArgument& arg = _currentArgs[iarg];
      arg.key = _postArgs[iarg].key;
      arg.value = _postArgs[iarg].value;
    }
    _currentArgCount = iarg;
    if (_postArgs) {
      delete[] _postArgs;
      _postArgs = nullptr;
      _postArgsLen = 0;
    }
    return true;
  }
  DBGWS("Error: line: %s\n", line.c_str());
  return false;
}

template <typename ServerType>
String ESP8266WebServerTemplate<ServerType>::urlDecode(const String& text)
{
  String decoded;
  char temp[] = "0x00";
  unsigned int len = text.length();
  unsigned int i = 0;
  while (i < len)
  {
    char decodedChar;
    char encodedChar = text.charAt(i++);
    if ((encodedChar == '%') && (i + 1 < len))
    {
      temp[2] = text.charAt(i++);
      temp[3] = text.charAt(i++);

      decodedChar = strtol(temp, NULL, 16);
    }
    else {
      if (encodedChar == '+')
      {
        decodedChar = ' ';
      }
      else {
        decodedChar = encodedChar;  // normal ascii char
      }
    }
    decoded += decodedChar;
  }
  return decoded;
}
#if 0
template <typename ServerType>
bool ESP8266WebServerTemplate<ServerType>::_parseFormUploadAborted(){
  _currentUpload->status = UPLOAD_FILE_ABORTED;
  if(_currentHandler && _currentHandler->canUpload(_currentUri))
    _currentHandler->upload(*this, _currentUri, *_currentUpload);
  return false;
}
#endif
//#include <vector>

template<typename ServerType>
class RequestHandler {
    using WebServerType = ESP8266WebServerTemplate<ServerType>;
public:
    virtual ~RequestHandler() { }
    virtual bool canHandle(HTTPMethod method, const String& uri) { (void) method; (void) uri; return false; }
    virtual bool canUpload(const String& uri) { (void) uri; return false; }
    virtual bool handle(WebServerType& server, HTTPMethod requestMethod, const String& requestUri) { (void) server; (void) requestMethod; (void) requestUri; return false; }
    virtual void upload(WebServerType& server, const String& requestUri, HTTPUpload& upload) { (void) server; (void) requestUri; (void) upload; }

    RequestHandler<ServerType>* next() { return _next; }
    void next(RequestHandler<ServerType>* r) { _next = r; }

private:
    RequestHandler<ServerType>* _next = nullptr;
	
protected:
    //std::vector<String> pathArgs;
    String pathArgs[10];

public:
    const String& pathArg(unsigned int i) { 
        return pathArgs[i];
    }
};

} // namespace

using ESP8266WebServer = esp8266webserver::ESP8266WebServerTemplate<EthernetServer>;
using RequestHandler = esp8266webserver::RequestHandler<EthernetServer>;


#endif

#endif /* _ETHERPORT_H_ */
#endif